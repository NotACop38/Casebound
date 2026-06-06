"""Tests for activity clustering into episodes (PRD FR15, Phase 4).

The load-bearing properties:

  1. Host, time, and principal proximity each shape the grouping: an episode never
     spans two hosts, a long quiet gap opens a new episode, and a handoff between
     two attributed principals opens a new episode while an unattributed event does
     not fragment a coherent run.
  2. Stable id: the same membership always yields the same episode id, surfaced as
     a tag on every member event, and clustering never moves an event_id.
  3. Sensible on the scenario: the showcase intrusion clusters into coherent
     episodes, with the benign noise separated by time and by principal.
"""

from __future__ import annotations

from pathlib import Path

from casebound.enrich import (
    DEFAULT_MAX_GAP_SECONDS,
    EPISODE_TAG_PREFIX,
    cluster_events,
    episode_id_for_tag,
    tag_events,
)
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, RawRef, normalize_records


def _event(
    *,
    offset_seconds: int,
    host: str | None = "HOST-1",
    principal: str | None = "CORP\\jdoe",
    action: str = "process_create",
    obj: str | None = None,
) -> Event:
    """Build a minimal canonical event at a given offset from a fixed base minute."""
    minute, second = divmod(offset_seconds, 60)
    assert 0 <= minute < 60 and 0 <= second < 60, "keep test offsets within the hour"
    stamp = f"2026-03-14T09:{minute:02d}:{second:02d}Z"
    return Event(
        datetime=stamp,
        timestamp_raw=stamp,
        source_timezone="UTC",
        timestamp_desc="logged",
        message="synthetic event for clustering",
        action=action,
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="x.csv", record=str(offset_seconds)),
        host=host,
        principal=principal,
        object=obj,
    )


# 1. Host, time, and principal proximity.


def test_a_long_time_gap_splits_into_two_episodes() -> None:
    # Two events 30s apart cluster together; a third more than the gap window after
    # the second (same host and principal) opens a fresh episode.
    a = _event(offset_seconds=0)
    b = _event(offset_seconds=30)
    assert len(cluster_events([a, b]).episodes) == 1

    far_seconds = 30 + DEFAULT_MAX_GAP_SECONDS + 60
    far_minute, far_second = divmod(far_seconds, 60)
    far_stamp = f"2026-03-14T09:{far_minute:02d}:{far_second:02d}Z"
    far_event = Event(
        datetime=far_stamp,
        timestamp_raw=far_stamp,
        source_timezone="UTC",
        timestamp_desc="logged",
        message="much later event",
        action="logon",
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="x.csv", record="far"),
        host="HOST-1",
        principal="CORP\\jdoe",
    )
    split = cluster_events([a, b, far_event])
    assert len(split.episodes) == 2
    assert split.episodes[0].event_count == 2
    assert split.episodes[1].event_count == 1


def test_different_hosts_never_share_an_episode() -> None:
    a = _event(offset_seconds=0, host="HOST-1")
    b = _event(offset_seconds=10, host="HOST-2")
    result = cluster_events([a, b])
    assert len(result.episodes) == 2
    hosts = {ep.host for ep in result.episodes}
    assert hosts == {"HOST-1", "HOST-2"}


def test_principal_handoff_splits_even_without_a_time_gap() -> None:
    a = _event(offset_seconds=0, principal="CORP\\alice")
    b = _event(offset_seconds=10, principal="CORP\\alice")
    c = _event(offset_seconds=20, principal="CORP\\bob")
    result = cluster_events([a, b, c])
    assert len(result.episodes) == 2
    assert result.episodes[0].principal == "CORP\\alice"
    assert result.episodes[0].event_count == 2
    assert result.episodes[1].principal == "CORP\\bob"


def test_unattributed_event_does_not_fragment_a_run() -> None:
    # A null-principal event between two same-principal events joins the run rather
    # than splitting it: an episode carries one named principal across the gap.
    a = _event(offset_seconds=0, principal="CORP\\jdoe")
    middle = _event(offset_seconds=20, principal=None)
    b = _event(offset_seconds=40, principal="CORP\\jdoe")
    result = cluster_events([a, middle, b])
    assert len(result.episodes) == 1
    assert result.episodes[0].event_count == 3
    assert result.episodes[0].principal == "CORP\\jdoe"


# 2. Stable id and tagging.


def test_episode_id_is_stable_across_runs() -> None:
    events = [_event(offset_seconds=0), _event(offset_seconds=15)]
    first = cluster_events(events).episodes
    second = cluster_events(events).episodes
    assert [ep.episode_id for ep in first] == [ep.episode_id for ep in second]


def test_member_events_carry_the_episode_tag() -> None:
    result = cluster_events([_event(offset_seconds=0), _event(offset_seconds=15)])
    episode = result.episodes[0]
    for event in result.events:
        assert episode.tag in event.tags
        assert episode_id_for_tag(episode.tag) == episode.episode_id
        assert episode.tag.startswith(EPISODE_TAG_PREFIX)


def test_clustering_never_moves_an_event_id() -> None:
    base = _event(offset_seconds=0)
    tagged = cluster_events([base]).events[0]
    assert tagged.event_id == base.event_id


def test_clustering_is_idempotent() -> None:
    events = [_event(offset_seconds=0), _event(offset_seconds=15)]
    once = cluster_events(events).events
    twice = cluster_events(once).events
    assert [event.tags for event in once] == [event.tags for event in twice]


# 3. Sensible on the showcase scenario.


def _scenario_events(tmp_path: Path) -> list[Event]:
    csv_path, _ = write_samples(tmp_path)
    result = normalize_records(HayabusaAdapter().read(csv_path))
    assert result.problem_count == 0
    return tag_events(result.events)


def test_scenario_clusters_sensibly(tmp_path: Path) -> None:
    events = _scenario_events(tmp_path)
    result = cluster_events(events)

    # Every event lands in exactly one episode, and no episode spans two hosts.
    placed = [eid for ep in result.episodes for eid in ep.event_ids]
    assert sorted(placed) == sorted(event.event_id for event in events)
    assert len(placed) == len(set(placed))

    by_id = {event.event_id: event for event in events}
    for episode in result.episodes:
        hosts = {by_id[eid].host for eid in episode.event_ids}
        assert len(hosts) == 1
        # An episode carries at most one distinct account (a DOMAIN\\user and the
        # same bare user are the same actor, so they do not count as two).
        principals = [by_id[eid].principal for eid in episode.event_ids]
        accounts = {p.rsplit("\\", 1)[-1].lower() for p in principals if p is not None}
        assert len(accounts) <= 1

    # The benign morning logon (well before the intrusion) is its own episode,
    # separated from the first intrusion event by far more than the gap window.
    episode_of = {eid: ep.episode_id for ep in result.episodes for eid in ep.event_ids}
    morning = next(e for e in events if e.datetime == "2026-03-14T08:30:05Z")
    first_intrusion = next(e for e in events if e.datetime == "2026-03-14T08:42:17Z")
    assert episode_of[morning.event_id] != episode_of[first_intrusion.event_id]

    # The dense workstation intrusion burst (08:42 to 08:48) is one episode, even
    # though several of its events carry a null principal: unattributed events do
    # not fragment a coherent run.
    burst = [
        e
        for e in events
        if "2026-03-14T08:42:17Z" <= e.datetime <= "2026-03-14T08:48:22Z"
        and e.host == "WIN-ACCT-07"
    ]
    burst_episodes = {episode_of[e.event_id] for e in burst}
    assert len(burst_episodes) == 1

    # The file-server activity (one actor, svc-backup, spelled with and without its
    # domain, plus interleaved unattributed events) clusters into a single episode.
    server_events = [e for e in events if e.host == "WIN-FILE-02"]
    server_episodes = {episode_of[e.event_id] for e in server_events}
    assert len(server_episodes) == 1
    server_episode = next(ep for ep in result.episodes if ep.host == "WIN-FILE-02")
    assert server_episode.principal == "CORP\\svc-backup"
