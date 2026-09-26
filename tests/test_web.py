"""Tests for the optional web viewer (PRD Section 8, decision D4).

The load-bearing properties:

  1. No logic fork: the report the viewer serves for the bundled demo case is byte
     for byte the report ``casebound demo`` writes, because both run the same
     pipeline and the same renderer.
  2. Every tool-output source the viewer accepts can be uploaded, analyzed, and
     browsed; raw artifacts and generic CSV stay on the command line.
  3. Upload hardening: cross-site and cross-origin posts, a missing or oversized
     Content-Length, a wrong suffix or content type, a non-UTF-8 body, and evidence
     that parses to nothing are each refused with a precise status, before any
     case is stored.
  4. The store is bounded: old uploads are evicted, the demo case never is.
  5. Autoescaping: hostile content in an uploaded file cannot inject markup.

The web dependencies live in the opt-in ``web`` extra; the module is skipped when
they are not installed. No network (the test client is in-process), no API keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi", reason="web extra not installed")

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from casebound.cli import app as cli_app
from casebound.generate import generate
from casebound.web.app import UPLOAD_SOURCES, create_app
from casebound.web.case import DEMO_CASE_ID, sanitize_upload_name

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# One file per accepted upload source: (source, file name, bytes, content type).
UPLOADS: dict[str, tuple[str, bytes, str]] = {
    "hayabusa": ("timeline.csv", generate().csv_text.encode("utf-8"), "text/csv"),
    "chainsaw": (
        "detections.json",
        (FIXTURES / "chainsaw_detections.json").read_bytes(),
        "application/json",
    ),
    "eztools": ("mft.csv", (FIXTURES / "eztools_mft_slice.csv").read_bytes(), "text/csv"),
    "velociraptor": (
        "evtx.jsonl",
        (FIXTURES / "velociraptor_evtx.jsonl").read_bytes(),
        "application/octet-stream",
    ),
    "plaso": ("supertimeline.csv", (FIXTURES / "plaso_l2t.csv").read_bytes(), "text/csv"),
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app())


def _upload(
    client: TestClient,
    source: str | None,
    name: str,
    body: bytes,
    content_type: str = "text/csv",
    **kwargs: Any,
) -> Any:
    data = {} if source is None else {"source": source}
    return client.post(
        "/upload",
        data=data,
        files={"file": (name, body, content_type)},
        follow_redirects=False,
        **kwargs,
    )


# 1. No logic fork.


def test_demo_report_is_the_cli_demo_report(client: TestClient, tmp_path: Path) -> None:
    result = CliRunner().invoke(cli_app, ["demo", "-o", str(tmp_path)])
    assert result.exit_code == 0, result.output
    served = client.get(f"/cases/{DEMO_CASE_ID}/report")
    assert served.status_code == 200
    assert served.text == (tmp_path / "report.html").read_text(encoding="utf-8")


def test_index_lists_cases_and_the_accepted_sources(client: TestClient) -> None:
    page = client.get("/")
    assert page.status_code == 200
    assert f'href="/cases/{DEMO_CASE_ID}/timeline"' in page.text
    assert "verified narrative" in page.text
    options = [line for line in page.text.splitlines() if "<option" in line]
    assert [option.split('"')[1] for option in options] == list(UPLOAD_SOURCES)
    assert 'accept=".csv,.json,.jsonl"' in page.text


def test_timeline_lists_events_with_techniques_and_links_the_report(client: TestClient) -> None:
    page = client.get(f"/cases/{DEMO_CASE_ID}/timeline")
    assert page.status_code == 200
    assert f'href="/cases/{DEMO_CASE_ID}/report"' in page.text
    assert page.text.count("<tr>") == 37 + 1  # every event plus the header row
    assert 'title="Command and Scripting Interpreter: PowerShell">T1059.001<' in page.text
    assert "2026-03-14 08:42:17 UTC" in page.text
    assert 'class="sev sev-high"' in page.text


def test_pages_are_self_contained(client: TestClient) -> None:
    for path in ("/", f"/cases/{DEMO_CASE_ID}/timeline", f"/cases/{DEMO_CASE_ID}/report"):
        html = client.get(path).text
        assert "<script" not in html
        assert "<link" not in html
        assert "http://" not in html and "https://" not in html


def test_unknown_case_is_not_found(client: TestClient) -> None:
    for suffix in ("timeline", "report"):
        assert client.get(f"/cases/nope/{suffix}").status_code == 404


def test_api_documentation_endpoints_are_disabled(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


# 2. Every accepted source.


@pytest.mark.parametrize("source", UPLOAD_SOURCES)
def test_each_accepted_source_uploads_and_browses(source: str) -> None:
    client = TestClient(create_app())
    name, body, content_type = UPLOADS[source]
    response = _upload(client, source, name, body, content_type)
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location == "/cases/upload-1/timeline"
    timeline = client.get(location)
    assert timeline.status_code == 200
    assert f"{source}: {name}" in timeline.text
    assert client.get("/cases/upload-1/report").status_code == 200
    assert "/cases/upload-1/timeline" in client.get("/").text


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        (None, "choose a source"),
        ("evtx", "choose a source"),
        ("generic_csv", "choose a source"),
        ("bogus", "choose a source"),
    ],
)
def test_sources_outside_the_upload_set_are_refused(source: str | None, detail: str) -> None:
    client = TestClient(create_app())
    response = _upload(client, source, "timeline.csv", b"Timestamp\n")
    assert response.status_code == 400
    assert detail in response.json()["detail"]


# 3. Upload hardening.


@pytest.mark.parametrize(
    ("source", "name", "content_type", "detail"),
    [
        ("hayabusa", "timeline.exe", "text/csv", "unsupported file type .exe"),
        ("chainsaw", "detections.csv", "text/csv", "expected .json"),
        ("hayabusa", "noextension", "text/csv", "unsupported file type (none)"),
        ("hayabusa", "timeline.csv", "image/png", "unsupported content type image/png"),
    ],
)
def test_wrong_type_is_refused_with_415(
    source: str, name: str, content_type: str, detail: str
) -> None:
    client = TestClient(create_app())
    response = _upload(client, source, name, b"Timestamp\n", content_type)
    assert response.status_code == 415
    assert detail in response.json()["detail"]


def test_non_utf8_body_is_refused_with_415() -> None:
    client = TestClient(create_app())
    response = _upload(client, "hayabusa", "timeline.csv", b"\xff\xfe\x00\x01binary")
    assert response.status_code == 415
    assert "UTF-8" in response.json()["detail"]


def test_evidence_that_parses_to_nothing_is_refused_with_422() -> None:
    client = TestClient(create_app())
    generic = (FIXTURES / "generic_edr_slice.csv").read_bytes()
    wrong_source = _upload(client, "hayabusa", "edr.csv", generic)
    assert wrong_source.status_code == 422
    assert (
        "no events could be parsed from the upload as hayabusa output"
        in (wrong_source.json()["detail"])
    )
    broken_json = _upload(client, "chainsaw", "detections.json", b"{not json", "application/json")
    assert broken_json.status_code == 422
    assert broken_json.json()["detail"] == "the upload could not be parsed as chainsaw output"
    # Nothing was stored for either failure.
    assert "/cases/upload-" not in client.get("/").text


def test_oversized_body_is_refused_with_413() -> None:
    client = TestClient(create_app(max_upload_bytes=1024))
    name, body, content_type = UPLOADS["hayabusa"]
    assert len(body) > 1024
    assert _upload(client, "hayabusa", name, body, content_type).status_code == 413


def test_oversized_declared_length_is_refused_before_parsing() -> None:
    # The file part is under the cap, but the declared body is over the cap plus
    # the framing allowance, so only the pre-parse header gate can refuse it.
    client = TestClient(create_app(max_upload_bytes=1024))
    response = client.post(
        "/upload",
        data={"source": "hayabusa", "note": "x" * (1024 * 1024)},
        files={"file": ("timeline.csv", b"Timestamp\n", "text/csv")},
    )
    assert response.status_code == 413


def test_upload_without_content_length_is_refused_with_411() -> None:
    client = TestClient(create_app())
    body = (
        b"--boundary\r\n"
        b'Content-Disposition: form-data; name="file"; filename="timeline.csv"\r\n'
        b"Content-Type: text/csv\r\n\r\n"
        b"Timestamp\r\n"
        b"--boundary--\r\n"
    )
    response = client.post(
        "/upload",
        content=iter([body]),  # an iterator body is sent chunked, with no length
        headers={"content-type": "multipart/form-data; boundary=boundary"},
    )
    assert response.status_code == 411


def test_non_numeric_content_length_is_refused_with_400() -> None:
    client = TestClient(create_app())
    response = client.post(
        "/upload", content=b"x", headers={"content-length": "lots", "content-type": "text/plain"}
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Content-Length is not a number"


@pytest.mark.parametrize(
    "headers",
    [
        {"sec-fetch-site": "cross-site"},
        {"sec-fetch-site": "same-site"},
        {"origin": "http://evil.example"},
    ],
)
def test_cross_site_and_cross_origin_posts_are_refused(headers: dict[str, str]) -> None:
    client = TestClient(create_app())
    name, body, content_type = UPLOADS["hayabusa"]
    response = _upload(client, "hayabusa", name, body, content_type, headers=headers)
    assert response.status_code == 403


def test_same_origin_post_passes_the_gates() -> None:
    client = TestClient(create_app())
    name, body, content_type = UPLOADS["hayabusa"]
    response = _upload(
        client,
        "hayabusa",
        name,
        body,
        content_type,
        headers={"sec-fetch-site": "same-origin", "origin": "http://testserver"},
    )
    assert response.status_code == 303


def test_upload_without_a_file_field_is_a_clean_400() -> None:
    client = TestClient(create_app())
    response = client.post("/upload", data={"source": "hayabusa"})
    assert response.status_code == 400
    assert response.json()["detail"] == "missing 'file' upload field"


# 4. The bounded store.


def test_old_uploads_are_evicted_and_the_demo_case_is_kept() -> None:
    client = TestClient(create_app(max_cases=2))
    name, body, content_type = UPLOADS["plaso"]
    for _ in range(3):
        assert _upload(client, "plaso", name, body, content_type).status_code == 303
    index = client.get("/").text
    assert f"/cases/{DEMO_CASE_ID}/timeline" in index
    assert "/cases/upload-3/timeline" in index
    assert "/cases/upload-1/timeline" not in index
    assert client.get("/cases/upload-1/timeline").status_code == 404


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("timeline.csv", "timeline.csv"),
        ("../../etc/passwd.csv", "passwd.csv"),
        ("C:\\Users\\x\\evil.csv", "evil.csv"),
        ("", "upload.csv"),
        ("..", "upload.csv"),
        ("notes", "notes.csv"),
    ],
)
def test_upload_names_are_reduced_to_a_safe_base_name(filename: str, expected: str) -> None:
    assert sanitize_upload_name(filename, ".csv") == expected


# 5. Escaping.


def test_hostile_upload_content_is_escaped() -> None:
    client = TestClient(create_app())
    detections = json.loads((FIXTURES / "chainsaw_detections.json").read_text(encoding="utf-8"))
    detections[0]["name"] = "<script>alert('xss')</script>"
    body = json.dumps(detections).encode("utf-8")
    assert _upload(client, "chainsaw", "d.json", body, "application/json").status_code == 303
    for path in ("/cases/upload-1/timeline", "/cases/upload-1/report"):
        html = client.get(path).text
        assert "<script>alert" not in html
    assert "&lt;script&gt;" in client.get("/cases/upload-1/report").text
