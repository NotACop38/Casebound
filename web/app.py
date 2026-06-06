"""The minimal Casebound web UI (PRD Section 8, decision D4, Phase 9).

A small FastAPI app that loads a case, browses the timeline, and views the report,
reusing the existing report layer unchanged. It is the optional stretch viewer: the
deterministic core and the CLI do not depend on it, and a default install pulls in
no web framework (the dependencies live in the opt-in ``web`` extra).

What it serves:

  - ``GET /``                       the case list and the upload form.
  - ``GET /cases/{id}/timeline``    a browsable timeline of the case events.
  - ``GET /cases/{id}/report``      the self-contained HTML report, rendered by the
                                    unchanged report layer (identical to the CLI's).
  - ``POST /upload``                accept a Hayabusa CSV timeline and load it.

Offline and no-egress guarantees (Hard rule 2, PRD Section 6). The app makes no
outbound network call: it imports no HTTP client, opens no socket of its own, and
the report it serves is self-contained (no asset is fetched at view time). The
server binds to loopback only by default (``serve``). Evidence never leaves the
host.

Upload hardening. Any upload is bounded and typed before it is touched: the
filename must be a ``.csv`` and the content type must be a text or CSV type; the
body is streamed with a hard byte cap and rejected past it; the bytes must decode
as UTF-8 text. The upload is then parsed read-only as a Hayabusa CSV timeline. It
is never opened as a program, executed, or fetched from anywhere, and no URL or
path the client supplies is ever dereferenced. An upload that yields no events is
rejected rather than rendered.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from web.case import (
    DEMO_CASE_ID,
    Case,
    build_demo_case,
    build_uploaded_case,
    case_report_model,
    render_case_report,
)

__all__ = [
    "DEFAULT_MAX_CASES",
    "DEFAULT_MAX_UPLOAD_BYTES",
    "create_app",
    "serve",
]

# The default upload ceiling: 5 MiB is generous for a triage CSV and small enough
# to bound memory and reject a runaway upload. Configurable per app instance.
DEFAULT_MAX_UPLOAD_BYTES = 5 * 1024 * 1024

# How many cases to retain in memory. The demo case is always kept; the oldest
# uploaded cases are evicted past this cap so a long-running process is bounded.
DEFAULT_MAX_CASES = 16

# Accepted upload file extensions and content types. The MVP ingests Hayabusa CSV
# only, so the type gate is narrow: a .csv name and a text or CSV content type.
# octet-stream and an empty type are allowed because some browsers send those for a
# .csv; the body is still validated as UTF-8 text and parsed as CSV before use.
_ALLOWED_SUFFIXES = frozenset({".csv"})
_ALLOWED_CONTENT_TYPES = frozenset(
    {
        "text/csv",
        "application/csv",
        "application/vnd.ms-excel",
        "text/plain",
        "application/octet-stream",
        "",
    }
)

# Streamed-read chunk size for the bounded upload reader.
_UPLOAD_CHUNK = 64 * 1024

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class CaseStore:
    """An in-memory, insertion-ordered store of loaded cases.

    The demo case is pinned and never evicted; uploaded cases are evicted oldest
    first once the cap is exceeded, so memory stays bounded over a long run.
    """

    def __init__(self, *, max_cases: int) -> None:
        self._cases: OrderedDict[str, Case] = OrderedDict()
        self._max_cases = max(1, max_cases)
        self._counter = 0

    def put(self, case: Case) -> None:
        """Store a case, evicting the oldest uploaded case if over the cap."""
        self._cases[case.case_id] = case
        while len(self._cases) > self._max_cases:
            evicted = False
            for case_id in list(self._cases):
                if case_id != DEMO_CASE_ID:
                    del self._cases[case_id]
                    evicted = True
                    break
            if not evicted:
                break

    def get(self, case_id: str) -> Case | None:
        """Return the case with this id, or None if it is not loaded."""
        return self._cases.get(case_id)

    def all(self) -> list[Case]:
        """Return every loaded case in insertion order."""
        return list(self._cases.values())

    def next_upload_id(self) -> str:
        """Return a fresh, unique id for an uploaded case."""
        self._counter += 1
        return f"upload-{self._counter}"


def _environment() -> Environment:
    """Build the Jinja2 environment for the UI templates, autoescaping on.

    Autoescaping is on so evidence-derived strings (hosts, principals, object
    paths) cannot inject markup into the timeline or the index.
    """
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _case_summary(case: Case) -> dict[str, Any]:
    """Build the small, render-ready summary the index and timeline header show."""
    return {
        "case_id": case.case_id,
        "title": case.title,
        "source_label": case.source_label,
        "scenario": case.scenario,
        "event_count": case.event_count,
        "is_demo": case.case_id == DEMO_CASE_ID,
        "has_narrative": case.has_narrative,
    }


async def _read_upload(file: UploadFile, max_bytes: int) -> str:
    """Validate the type and size of an upload and return its decoded text.

    Enforces the type gate (a .csv name and an allowed content type), streams the
    body with a hard byte cap, and decodes it as UTF-8. Raises ``HTTPException``
    with a precise status on any violation: 415 for a wrong type or non-text body,
    413 for an oversized body. The bytes are only ever treated as CSV text.
    """
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in _ALLOWED_SUFFIXES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"unsupported file type {suffix or '(none)'}; only .csv is accepted",
        )

    content_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if content_type not in _ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"unsupported content type {content_type or '(none)'}; expected a CSV",
        )

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_UPLOAD_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"upload exceeds the {max_bytes} byte limit",
            )
        chunks.append(chunk)

    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="upload is not valid UTF-8 text; expected a CSV timeline",
        ) from exc


def create_app(
    *,
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
    max_cases: int = DEFAULT_MAX_CASES,
) -> FastAPI:
    """Build the Casebound web UI application.

    Seeds the store with the bundled demo case so the UI is useful immediately,
    offline and with no keys. ``max_upload_bytes`` caps any upload; ``max_cases``
    bounds the in-memory store. The API docs endpoints are disabled to keep the
    surface minimal.
    """
    app = FastAPI(
        title="Casebound",
        description="Local-first DFIR investigation copilot: browsable timeline and report.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    env = _environment()
    store = CaseStore(max_cases=max_cases)
    store.put(build_demo_case())

    def _render(template_name: str, **context: Any) -> HTMLResponse:
        template = env.get_template(template_name)
        return HTMLResponse(template.render(**context))

    def _require_case(case_id: str) -> Case:
        case = store.get(case_id)
        if case is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"no case loaded with id {case_id!r}"
            )
        return case

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return _render(
            "index.html.j2",
            cases=[_case_summary(case) for case in store.all()],
            max_upload_kib=max_upload_bytes // 1024,
        )

    @app.get("/cases/{case_id}/timeline", response_class=HTMLResponse)
    def timeline(case_id: str) -> HTMLResponse:
        case = _require_case(case_id)
        model = case_report_model(case)
        return _render(
            "timeline.html.j2",
            case=_case_summary(case),
            stats=model.stats,
            events=model.events,
            observed_techniques=model.observed_techniques,
        )

    @app.get("/cases/{case_id}/report", response_class=HTMLResponse)
    def report(case_id: str) -> HTMLResponse:
        case = _require_case(case_id)
        # The unchanged report layer renders the hero deliverable: identical to
        # the report the CLI writes for the same case (no logic fork).
        return HTMLResponse(render_case_report(case))

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)) -> Response:
        csv_text = await _read_upload(file, max_upload_bytes)
        case_id = store.next_upload_id()
        case, _problems = build_uploaded_case(case_id, file.filename or "upload.csv", csv_text)
        if case.event_count == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="no timeline events could be parsed from the upload (expected Hayabusa CSV)",
            )
        store.put(case)
        # Redirect to the browsable timeline for the freshly loaded case.
        return RedirectResponse(
            url=f"/cases/{case_id}/timeline", status_code=status.HTTP_303_SEE_OTHER
        )

    return app


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the web UI with uvicorn, bound to loopback by default.

    Loopback-only by default keeps the viewer local to the host, consistent with
    the offline, evidence-sovereign posture (Hard rule 2). uvicorn is imported
    lazily so importing this module pulls in no server machinery.
    """
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port)
