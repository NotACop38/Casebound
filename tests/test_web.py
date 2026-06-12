"""Tests for the optional web UI (PRD Section 8, decision D4, Phase 9).

The load-bearing properties:

  1. Happy path is the CLI report: the report the web app serves for the bundled
     demo case is byte for byte the report ``casebound demo`` writes, because the
     web layer reuses the report renderer unchanged (no logic fork).
  2. Browse the timeline: the timeline page lists the case events and links to the
     full report.
  3. Upload hardening: an oversized upload is rejected (413) and a wrong-type
     upload is rejected (415), before the body is parsed; a malformed CSV that
     yields no events is rejected (422).
  4. Offline and no-egress: the served report and timeline are self-contained (no
     asset is fetched at view time), and serving the UI opens no outbound socket.
  5. Autoescaping: hostile content in an uploaded timeline cannot inject markup.

The web dependencies live in the opt-in ``web`` extra; the module is skipped when
they are not installed, so the core suite stays green without them. All tests run
offline with no API keys; the demo narrative uses the bundled offline narrator.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest

pytest.importorskip("fastapi", reason="web extra not installed")
pytest.importorskip("httpx", reason="web extra not installed")

from casebound.cli import run_demo
from casebound.narrate import OfflineDemoNarrator
from fastapi import FastAPI
from fastapi.testclient import TestClient
from web.app import create_app
from web.case import DEMO_CASE_ID

# A small Hayabusa CSV matching the synthetic generator's verbose columns, enough
# to normalize into one process-create event. Used for the upload happy path and
# the escaping test.
_HAYABUSA_HEADER = (
    "Timestamp,Computer,Channel,EventID,Level,MitreTactics,MitreTags,RecordID,RuleTitle,Details"
)
_HAYABUSA_ROW = (
    "2026-03-14 08:42:17.000 +00:00,WIN-ACCT-07,Security,4688,high,Execution,"
    "T1059.001,4711,Encoded PowerShell spawned from Word,"
    '"CommandLine: powershell -enc ZQBjAGgAbwA= | Process: powershell.exe"'
)


def _sample_csv() -> str:
    return f"{_HAYABUSA_HEADER}\n{_HAYABUSA_ROW}\n"


def _client(**kwargs: int) -> TestClient:
    app: FastAPI = create_app(**kwargs)
    return TestClient(app)


def _assert_self_contained(html: str) -> None:
    # No external fetches of any kind at view time (FR28, Hard rule 2).
    assert "<!DOCTYPE html>" in html
    assert "<script" not in html
    assert "<link" not in html
    assert 'src="http' not in html
    assert 'href="http' not in html
    assert "@import" not in html


def test_happy_path_report_matches_the_cli_report(tmp_path: Path) -> None:
    # The CLI writes the demo report with the offline narrator in a single pass;
    # the web app serves the demo case rendered by the same report layer. They must
    # be byte for byte identical, proving the viewer does not fork the report logic.
    cli = run_demo(
        tmp_path,
        model=OfflineDemoNarrator(),
        model_label=OfflineDemoNarrator.LABEL,
        max_rounds=0,
    )
    cli_html = cli.report_path.read_text(encoding="utf-8")

    resp = _client().get(f"/cases/{DEMO_CASE_ID}/report")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert resp.text == cli_html


def test_index_lists_the_demo_case() -> None:
    resp = _client().get("/")
    assert resp.status_code == 200
    _assert_self_contained(resp.text)
    assert "Loaded cases" in resp.text
    assert f"/cases/{DEMO_CASE_ID}/timeline" in resp.text
    assert f"/cases/{DEMO_CASE_ID}/report" in resp.text


def test_timeline_browses_events_and_links_to_the_report() -> None:
    resp = _client().get(f"/cases/{DEMO_CASE_ID}/timeline")
    assert resp.status_code == 200
    _assert_self_contained(resp.text)
    # The browsable timeline shows the scenario events and links to the full report.
    assert "T1059.001" in resp.text
    assert f"/cases/{DEMO_CASE_ID}/report" in resp.text


def test_report_is_self_contained() -> None:
    resp = _client().get(f"/cases/{DEMO_CASE_ID}/report")
    assert resp.status_code == 200
    _assert_self_contained(resp.text)


def test_unknown_case_is_not_found() -> None:
    client = _client()
    assert client.get("/cases/nope/report").status_code == 404
    assert client.get("/cases/nope/timeline").status_code == 404


def test_upload_happy_path_loads_a_browsable_case() -> None:
    client = _client()
    files = {"file": ("triage.csv", _sample_csv(), "text/csv")}
    resp = client.post("/upload", files=files, follow_redirects=False)

    # The upload is accepted and redirects to the new case's timeline.
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith("/cases/upload-")
    assert location.endswith("/timeline")

    timeline = client.get(location)
    assert timeline.status_code == 200
    assert "WIN-ACCT-07" in timeline.text
    # The uploaded case takes the deterministic no-model path (no narrative).
    report = client.get(location.replace("/timeline", "/report"))
    assert report.status_code == 200
    assert "No language model configured" in report.text


def test_oversized_upload_is_rejected() -> None:
    # A tiny limit makes the size guard cheap to exercise. A body past the cap is
    # rejected with 413 before it is parsed.
    client = _client(max_upload_bytes=512)
    oversized = _HAYABUSA_HEADER + "\n" + ("x" * 4096) + "\n"
    files = {"file": ("big.csv", oversized, "text/csv")}
    resp = client.post("/upload", files=files)
    assert resp.status_code == 413


def test_wrong_type_upload_is_rejected() -> None:
    client = _client()
    # A non-CSV type is rejected with 415, by extension and by content type.
    png = {"file": ("evil.png", b"\x89PNG\r\n\x1a\n", "image/png")}
    assert client.post("/upload", files=png).status_code == 415
    # A .json with a JSON content type is rejected too.
    js = {"file": ("data.json", b"{}", "application/json")}
    assert client.post("/upload", files=js).status_code == 415


def test_binary_csv_upload_is_rejected() -> None:
    # A .csv name carrying non-UTF-8 bytes is rejected as not-text (415), so binary
    # content can never reach the CSV parser.
    client = _client()
    files = {"file": ("weird.csv", b"\xff\xfe\x00\x01binary", "text/csv")}
    assert client.post("/upload", files=files).status_code == 415


def test_unparseable_csv_yields_no_events_and_is_rejected() -> None:
    # A CSV that normalizes to zero events is rejected (422) rather than rendered as
    # an empty report.
    client = _client()
    files = {"file": ("notes.csv", "alpha,beta\n1,2\n", "text/csv")}
    assert client.post("/upload", files=files).status_code == 422


def test_uploaded_timeline_escapes_hostile_content() -> None:
    # An uploaded row whose field carries markup must never inject it into the page.
    client = _client()
    hostile_row = (
        "2026-03-14 08:42:17.000 +00:00,<script>alert(1)</script>,Security,4688,high,"
        "Execution,T1059.001,4712,XSS attempt,"
        '"CommandLine: powershell.exe | Process: powershell.exe"'
    )
    csv_text = f"{_HAYABUSA_HEADER}\n{hostile_row}\n"
    files = {"file": ("xss.csv", csv_text, "text/csv")}
    resp = client.post("/upload", files=files, follow_redirects=True)
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


class _NetworkAccessError(AssertionError):
    """Raised when serving the UI attempts to open a network connection."""


def _deny(*_args: object, **_kwargs: object) -> NoReturn:
    raise _NetworkAccessError("the web UI attempted outbound network access")


@pytest.fixture
def no_outbound_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Block the outbound socket primitives so any egress attempt fails loudly."""
    monkeypatch.setattr(socket, "getaddrinfo", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    yield


def test_serving_the_ui_makes_no_outbound_connection(no_outbound_sockets: None) -> None:
    # Building the app (which builds the demo case) and serving every page must not
    # open an outbound connection: the in-process client proves the request path is
    # network-free.
    client = _client()
    assert client.get("/").status_code == 200
    assert client.get(f"/cases/{DEMO_CASE_ID}/timeline").status_code == 200
    assert client.get(f"/cases/{DEMO_CASE_ID}/report").status_code == 200


def test_network_guard_blocks_real_connections(no_outbound_sockets: None) -> None:
    # Prove the guard has teeth, so the no-call result above is meaningful.
    with pytest.raises(_NetworkAccessError):
        socket.create_connection(("203.0.113.1", 9))


# 6. Upload ingress gates: the header checks run before the body is parsed.


def test_cross_site_upload_is_refused() -> None:
    # A hostile page in the operator's browser can send a form POST at the
    # loopback server without CORS (CORS only gates reading the response). Fetch
    # metadata identifies it and the gate refuses it before any parsing.
    client = _client()
    files = {"file": ("timeline.csv", _sample_csv(), "text/csv")}
    resp = client.post("/upload", files=files, headers={"sec-fetch-site": "cross-site"})
    assert resp.status_code == 403


def test_cross_origin_upload_is_refused_by_origin_header() -> None:
    client = _client()
    files = {"file": ("timeline.csv", _sample_csv(), "text/csv")}
    resp = client.post("/upload", files=files, headers={"origin": "http://evil.example"})
    assert resp.status_code == 403


def test_same_origin_upload_passes_the_gates() -> None:
    client = _client()
    files = {"file": ("timeline.csv", _sample_csv(), "text/csv")}
    resp = client.post(
        "/upload",
        files=files,
        headers={"sec-fetch-site": "same-origin", "origin": "http://testserver"},
        follow_redirects=False,
    )
    assert resp.status_code == 303


def test_upload_without_content_length_is_refused() -> None:
    # A chunked request declares no Content-Length, so the size gate cannot hold
    # the parser to a bound; it is refused before the body is read.
    client = _client()
    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="timeline.csv"\r\n'
        b"Content-Type: text/csv\r\n\r\n"
        b"Timestamp\r\n"
        b"--boundary--\r\n"
    )
    resp = client.post(
        "/upload",
        content=iter([body]),  # an iterator body is sent chunked, with no length
        headers={"content-type": "multipart/form-data; boundary=boundary"},
    )
    assert resp.status_code == 411


def test_oversized_declared_length_is_refused_before_parsing() -> None:
    # The declared Content-Length alone trips the gate: the handler never parses
    # the multipart body of a request that announces more than the cap allows.
    client = _client(max_upload_bytes=1024)
    files = {"file": ("timeline.csv", "x" * (1024 * 1024), "text/csv")}
    resp = client.post("/upload", files=files)
    assert resp.status_code == 413


def test_upload_without_a_file_field_is_a_clean_400() -> None:
    client = _client()
    resp = client.post("/upload", data={"note": "no file here"})
    assert resp.status_code == 400
