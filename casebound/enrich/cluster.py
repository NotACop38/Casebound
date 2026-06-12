"""Activity clustering into episodes (PRD FR15).

Groups normalized events into activity episodes by time, host, and principal
proximity, then surfaces each episode as a stable id tag on its member events.
No model is in this loop: an episode is a pure function of the events' core
fields, so the same events always yield the same episodes and the same ids.

The grouping rule, stated precisely so it is auditable:

  1. Host proximity: an episode never spans two hosts. Events are grouped by host
     first (a missing host is its own group), so an episode is always one system's
     activity.

  2. Time proximity: within one host, events are ordered by time and a new episode
     starts wherever the gap to the previous event exceeds ``max_gap_seconds``
     (default 600, ten minutes). A dense burst is one episode; a later burst after
     a long quiet gap is a new one.

  3. Principal proximity: a new episode also starts on a principal handoff, that
     is when an attributed event names a different account than the run's current
     actor. The current actor is the most recent named (non-null) account in the
     run, not just the immediately previous event, so an unattributed event between
     two different actors does not bridge them into one episode. Accounts are
     compared on the bare account name (the segment after any ``DOMAIN\\`` prefix,
     case insensitively), so the same actor spelled ``CORP\\jdoe`` on one record
     and ``jdoe`` on another is treated as one actor, not a handoff. An
     unattributed event (a null principal, common on a raw telemetry record) never
     forces a split on its own: it joins the surrounding run rather than
     fragmenting a coherent burst of one actor's activity. The effect is that an
     episode carries at most one distinct account, while a different actor on the
     same host opens a new episode even with no time gap.

The episode id is a stable content hash of the sorted member event ids, so the
same membership always yields the same id and the id is an unforgeable handle to
exactly that set of events. It is surfaced on each member event as a
``tags`` entry of the form ``episode:EP-<short hash>`` (see ``EPISODE_TAG_PREFIX``),
which is what the report and any downstream consumer read to group the timeline.

Tagging returns copies: ``Event`` is frozen and its core identity fields are
unchanged, so an event's ``event_id`` never moves when it is placed in an episode
(episodes are addressing, not identity). The operation is idempotent: clustering
an already-tagged event set does not double-tag.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

from casebound.normalize.schema import Event

__all__ = [
    "DEFAULT_MAX_GAP_SECONDS",
    "EPISODE_TAG_PREFIX",
    "ClusterResult",
    "Episode",
    "cluster_events",
    "episode_id_for_tag",
]

# How long a quiet gap, in seconds, ends one episode and starts the next within a
# single host's stream. Ten minutes groups a dense burst of related activity while
# keeping a later, separate burst its own episode (FR15).
DEFAULT_MAX_GAP_SECONDS = 600

# The prefix used for the episode label written into an event's ``tags`` list, so
# an episode tag is unambiguous among any analyst tags that share the field.
EPISODE_TAG_PREFIX = "episode:"

# Domain-separation prefix folded into the hashed membership so episode ids cannot
# collide with any other content hash in the system.
_EPISODE_ID_NAMESPACE = "casebound-episode-v0.1"

# How many leading hex characters of the membership hash form the short id.
_SHORT_ID_LEN = 12

# The sentinel host key for events with a missing host. It is never a real host
# name, so host-less events group only with each other, never with a named host.
_UNATTRIBUTED = "\x00"


@dataclass(frozen=True)
class Episode:
    """One activity episode: a coherent run of one actor's events on one host.

    ``episode_id`` is the stable ``EP-<short hash>`` handle derived from the
    sorted member event ids. ``host`` is the shared host. ``principal`` is the
    episode's single distinct named principal, or None when its members were all
    unattributed. ``start`` and ``end`` are the first and last member datetimes
    (canonical UTC). ``event_ids`` are the member event ids in chronological order.
    """

    episode_id: str
    host: str | None
    principal: str | None
    start: str
    end: str
    event_ids: tuple[str, ...]

    @property
    def event_count(self) -> int:
        """The number of events in the episode."""
        return len(self.event_ids)

    @property
    def tag(self) -> str:
        """The ``tags`` entry written onto each member event for this episode."""
        return f"{EPISODE_TAG_PREFIX}{self.episode_id}"

    def to_dict(self) -> dict[str, object]:
        """Render the episode as a JSON-ready dict."""
        return {
            "episode_id": self.episode_id,
            "host": self.host,
            "principal": self.principal,
            "start": self.start,
            "end": self.end,
            "event_count": self.event_count,
            "event_ids": list(self.event_ids),
        }


@dataclass
class ClusterResult:
    """The output of one clustering run.

    ``episodes`` are the episodes in chronological order (by start time).
    ``events`` are the input events, in their original order, each returned as a
    copy carrying its episode tag in ``tags``.
    """

    episodes: list[Episode] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)


def episode_id_for_tag(tag: str) -> str | None:
    """Return the episode id embedded in a tag, or None if it is not an episode tag."""
    if tag.startswith(EPISODE_TAG_PREFIX):
        return tag[len(EPISODE_TAG_PREFIX) :]
    return None


def _parse_utc(value: str) -> datetime:
    """Parse a canonical UTC datetime string (trailing Z) into an aware instant."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _compute_episode_id(member_ids: Sequence[str]) -> str:
    """Return the stable ``EP-<short hash>`` id for a set of member event ids."""
    payload = "\n".join([_EPISODE_ID_NAMESPACE, *sorted(member_ids)])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"EP-{digest[:_SHORT_ID_LEN]}"


def _group_key(event: Event) -> str:
    """The host grouping key, with a sentinel for a missing host."""
    return event.host if event.host is not None else _UNATTRIBUTED


def _account(principal: str) -> str:
    """The bare account name used to compare principals: the part after DOMAIN\\."""
    return principal.rsplit("\\", 1)[-1].lower()


def _episode_principal(events: list[Event]) -> str | None:
    """The episode's representative principal, or None when every member is null.

    By the split rule an episode carries at most one distinct account. The most
    qualified spelling is preferred (one carrying a ``DOMAIN\\`` prefix over a bare
    account name) so the report shows the fullest available attribution.
    """
    named = [event.principal for event in events if event.principal is not None]
    if not named:
        return None
    accounts = {_account(principal) for principal in named}
    if len(accounts) != 1:
        return None
    qualified = [principal for principal in named if "\\" in principal]
    return qualified[0] if qualified else named[0]


def _split_into_episodes(events: list[Event], max_gap_seconds: int) -> list[Episode]:
    """Split one host's stream, already time-sorted, into episodes (time, principal).

    A new episode begins on a time gap beyond ``max_gap_seconds`` (time proximity)
    or on a principal handoff: an attributed event whose account differs from the
    run's current actor, the most recent named account in the run. A null principal
    never opens an episode on its own and never changes the run's current actor.
    """
    episodes: list[Episode] = []
    run: list[Event] = []
    previous_time: datetime | None = None
    run_account: str | None = None  # most recent named account in the current run

    def flush() -> None:
        if not run:
            return
        member_ids = tuple(event.event_id for event in run)
        episodes.append(
            Episode(
                episode_id=_compute_episode_id(member_ids),
                host=run[0].host,
                principal=_episode_principal(run),
                start=run[0].datetime,
                end=run[-1].datetime,
                event_ids=member_ids,
            )
        )

    for event in events:
        moment = _parse_utc(event.datetime)
        account = _account(event.principal) if event.principal is not None else None

        gapped = (
            previous_time is not None and (moment - previous_time).total_seconds() > max_gap_seconds
        )
        handoff = account is not None and run_account is not None and account != run_account
        if gapped or handoff:
            flush()
            run = []
            run_account = None

        run.append(event)
        previous_time = moment
        if account is not None:
            run_account = account
    flush()
    return episodes


def cluster_events(
    events: Iterable[Event],
    *,
    max_gap_seconds: int = DEFAULT_MAX_GAP_SECONDS,
) -> ClusterResult:
    """Cluster events into activity episodes and tag each member event (FR15).

    Events are grouped by host and then split on a time gap beyond
    ``max_gap_seconds`` or a principal handoff, so each episode is one actor's
    coherent, time-bounded run of activity on one host. Each returned event is a
    copy with its episode id appended to ``tags`` (idempotent: an already-present
    episode tag is not duplicated). The core identity fields, and therefore every
    ``event_id``, are unchanged.
    """
    materialized = list(events)

    groups: dict[str, list[Event]] = {}
    for event in materialized:
        groups.setdefault(_group_key(event), []).append(event)

    episodes: list[Episode] = []
    for group in groups.values():
        # Sort on the parsed instant, not the string: the canonical form trims
        # trailing zeros, so "...17.5Z" sorts before "...17Z" lexicographically
        # while being chronologically later.
        ordered = sorted(group, key=lambda e: (_parse_utc(e.datetime), e.event_id))
        episodes.extend(_split_into_episodes(ordered, max_gap_seconds))

    # Chronological order, with host and principal as stable tie-breakers so the
    # episode order is fully determined.
    episodes.sort(
        key=lambda ep: (_parse_utc(ep.start), ep.host or "", ep.principal or "", ep.episode_id)
    )

    tag_for_event: dict[str, str] = {}
    for episode in episodes:
        for event_id in episode.event_ids:
            tag_for_event[event_id] = episode.tag

    tagged: list[Event] = []
    for event in materialized:
        tag = tag_for_event.get(event.event_id)
        if tag is None or tag in event.tags:
            tagged.append(event)
            continue
        tagged.append(replace(event, tags=[*event.tags, tag]))

    return ClusterResult(episodes=episodes, events=tagged)
