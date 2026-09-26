"""The optional Casebound web viewer (PRD Section 8, decision D4).

A small FastAPI app that lists loaded cases, browses a case's timeline, and serves
its report. It is a viewer, not a second pipeline: every case is built by
``casebound.pipeline.analyze`` and every report is rendered by
``casebound.report.render_html``, so the page it serves is the report the command
line writes for the same evidence. The deterministic core and the CLI do not depend
on it, and a default install pulls in no web framework (the dependencies live in
the opt-in ``web`` extra).

Routes:

  - ``GET /``                       the case list and the upload form.
  - ``GET /cases/{id}/timeline``    a browsable timeline of the case's events.
  - ``GET /cases/{id}/report``      the self-contained HTML report.
  - ``POST /upload``                analyze an uploaded tool-output file.

Offline and no-egress guarantees (Hard rule 2, PRD Section 6). The app makes no
outbound network call: it imports no HTTP client, opens no socket of its own, and
the pages it serves fetch nothing at view time. ``serve`` binds to loopback by
default. Evidence never leaves the host.

Upload hardening. An upload is gated before its body is parsed: a browser-issued
cross-site POST is refused via fetch metadata and the Origin header, and the
request must declare a Content-Length within the cap, which the HTTP server then
enforces, so the multipart parser never receives (or spools) more than the bound.
The form must name a tool-output source the viewer accepts, and the file must then
pass that source's suffix gate, a text or JSON content-type gate, the exact byte
cap, and a UTF-8 decode before it is parsed read-only. It is never opened as a
program, executed, or fetched from anywhere, and no URL or path the client supplies
is ever dereferenced. An upload that yields no events is rejected with a 422
rather than rendered.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
from collections import OrderedDict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.datastructures import UploadFile

from casebound.pipeline import EmptyCaseError
from casebound.report import DEFAULT_HTML_MAX_EVENTS, build_report_model, render_html
from casebound.sources import SourceSpec, get_source
from casebound.web.case import DEMO_CASE_ID, LoadedCase, build_demo_case, build_uploaded_case

__all__ = [
    "DEFAULT_MAX_CASES",
    "DEFAULT_MAX_UPLOAD_BYTES",
    "UPLOAD_SOURCES",
    "CaseStore",
    "create_app",
    "serve",
]

# The default upload ceiling: 5 MiB is generous for a triage export and small
# enough to bound memory and reject a runaway upload. Configurable per app.
DEFAULT_MAX_UPLOAD_BYTES = 5 * 1024 * 1024

# How many cases to retain in memory. The demo case is always kept; the oldest
# uploaded cases are evicted past this cap so a long-running process is bounded.
DEFAULT_MAX_CASES = 16

# The sources an upload may name: the tool-output formats that need no column map
# and no optional extra. A raw artifact (.evtx, $MFT) is binary and needs the raw
# extra, and a generic CSV needs a mapping file, so both stay on the command line.
UPLOAD_SOURCES: tuple[str, ...] = ("hayabusa", "chainsaw", "eztools", "velociraptor", "plaso")

# Accepted content types. octet-stream and an empty type are allowed because
# browsers send those for suffixes they do not know (.jsonl, often .csv); the body
# is still decoded as UTF-8 text and parsed by the named source's reader.
_ALLOWED_CONTENT_TYPES = frozenset(
    {
        "",
        "application/csv",
        "application/json",
        "application/jsonl",
        "application/octet-stream",
        "application/vnd.ms-excel",
        "application/x-jsonlines",
        "application/x-ndjson",
        "text/csv",
        "text/plain",
    }
)

# Streamed-read chunk size for the bounded upload reader.
_UPLOAD_CHUNK = 64 * 1024

# Headroom on the declared Content-Length over the file cap: the multipart framing
# (boundary lines, part headers, the source field) costs a little beyond the file
# bytes. The exact per-file cap is still enforced when the part is read.
_MULTIPART_OVERHEAD = 64 * 1024


class CaseStore:
    """An in-memory, insertion-ordered store of loaded cases.

    The demo case is pinned and never evicted; uploaded cases are evicted oldest
    first once the cap is exceeded, so memory stays bounded over a long run.
    """

    def __init__(self, *, max_cases: int) -> None:
        self._cases: OrderedDict[str, LoadedCase] = OrderedDict()
        self._max_cases = max(1, max_cases)
        self._counter = 0

    def put(self, loaded: LoadedCase) -> None:
        """Store a case, evicting the oldest uploaded case if over the cap."""
        self._cases[loaded.case_id] = loaded
        while len(self._cases) > self._max_cases:
            evictable = next((key for key in self._cases if key != DEMO_CASE_ID), None)
            if evictable is None:
                break
            del self._cases[evictable]

    def get(self, case_id: str) -> LoadedCase | None:
        """Return the case with this id, or None if it is not loaded."""
        return self._cases.get(case_id)

    def all(self) -> list[LoadedCase]:
        """Return every loaded case in insertion order."""
        return list(self._cases.values())

    def next_upload_id(self) -> str:
        """Return a fresh, unique id for an uploaded case."""
        self._counter += 1
        return f"upload-{self._counter}"


def _environment() -> Environment:
    """Build the Jinja2 environment for the viewer templates, autoescaping on.

    Autoescaping is on so evidence-derived strings (hosts, principals, object
    paths) cannot inject markup into the timeline or the index.
    """
    env = Environment(
        loader=PackageLoader("casebound.web", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["utc"] = lambda value: (
        str(value).replace("T", " ").removesuffix("Z") + " UTC" if value else ""
    )
    return env


def _upload_specs() -> tuple[SourceSpec, ...]:
    return tuple(get_source(name) for name in UPLOAD_SOURCES)


def _case_summary(loaded: LoadedCase) -> dict[str, Any]:
    """The small, render-ready summary the index and the timeline header show."""
    case = loaded.case
    return {
        "case_id": loaded.case_id,
        "title": loaded.title,
        "source_label": loaded.source_label,
        "event_count": len(case.events),
        "problem_count": len(case.problems),
        "is_demo": loaded.case_id == DEMO_CASE_ID,
        "has_narrative": not case.no_model,
    }


def _enforce_upload_guards(request: Request, max_bytes: int) -> None:
    """Refuse a cross-site or oversized upload on the headers, before any parsing.

    FastAPI's ``File`` dependency would run the multipart parser to completion
    (spooling file parts to disk with no upper bound) before a handler could check
    anything, so the real ingress controls live here and the handler parses the
    form only after they pass:

      - A browser-issued cross-site POST is refused via fetch metadata and the
        Origin header. The viewer binds loopback, but a hostile page in the
        operator's browser could otherwise drive uploads cross-origin: sending a
        form POST needs no CORS, CORS only gates reading the response. Requests
        without browser headers (curl) are unaffected; CSRF needs a browser.
      - The request must declare a Content-Length within the cap (plus the
        multipart framing overhead). The HTTP server enforces that a body never
        exceeds its declared length, so the parser can never receive more than
        the bound; a request that declares no length is refused.
    """
    site = request.headers.get("sec-fetch-site")
    if site is not None and site not in ("same-origin", "none"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="cross-site uploads are refused")
    origin = request.headers.get("origin")
    if origin is not None and urlsplit(origin).netloc != request.headers.get("host", ""):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="cross-origin uploads are refused")

    declared = request.headers.get("content-length")
    if declared is None:
        raise HTTPException(
            status.HTTP_411_LENGTH_REQUIRED, detail="uploads must declare a Content-Length"
        )
    try:
        length = int(declared)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail="Content-Length is not a number"
        ) from exc
    if length > max_bytes + _MULTIPART_OVERHEAD:
        raise HTTPException(
            status.HTTP_413_CONTENT_TOO_LARGE, detail=f"upload exceeds the {max_bytes} byte limit"
        )


def _upload_source(value: object) -> SourceSpec:
    """Resolve the form's ``source`` field to an accepted upload source, or 400."""
    name = value.strip().lower() if isinstance(value, str) else ""
    if name not in UPLOAD_SOURCES:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"choose a source: one of {', '.join(UPLOAD_SOURCES)}",
        )
    return get_source(name)


async def _read_upload(file: UploadFile, spec: SourceSpec, max_bytes: int) -> str:
    """Validate the type and size of an upload and return its decoded text.

    Enforces the source's suffix gate and the content-type gate, streams the body
    with a hard byte cap, and decodes it as UTF-8. Raises ``HTTPException`` with a
    precise status on any violation: 415 for a wrong type or a non-text body, 413
    for an oversized body. The bytes are only ever treated as text.
    """
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in spec.suffixes:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"unsupported file type {suffix or '(none)'} for {spec.name}; "
                f"expected {', '.join(spec.suffixes)}"
            ),
        )

    content_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if content_type not in _ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"unsupported content type {content_type or '(none)'}; expected text or JSON",
        )

    chunks: list[bytes] = []
    total = 0
    while chunk := await file.read(_UPLOAD_CHUNK):
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"upload exceeds the {max_bytes} byte limit",
            )
        chunks.append(chunk)

    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="upload is not valid UTF-8 text"
        ) from exc


def create_app(
    *,
    max_upload_bytes: int = DEFAULT_MAX_UPLOAD_BYTES,
    max_cases: int = DEFAULT_MAX_CASES,
) -> FastAPI:
    """Build the Casebound web viewer application.

    Seeds the store with the bundled demo case so the viewer is useful immediately,
    offline and with no keys. ``max_upload_bytes`` caps any upload; ``max_cases``
    bounds the in-memory store. The API documentation endpoints are disabled to
    keep the surface minimal.
    """
    app = FastAPI(
        title="Casebound",
        description="Local, offline viewer for Casebound cases and reports.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    env = _environment()
    store = CaseStore(max_cases=max_cases)
    store.put(build_demo_case())
    upload_specs = _upload_specs()

    def _render(template_name: str, **context: Any) -> HTMLResponse:
        return HTMLResponse(env.get_template(template_name).render(**context))

    def _require_case(case_id: str) -> LoadedCase:
        loaded = store.get(case_id)
        if loaded is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="no case is loaded with that id")
        return loaded

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return _render(
            "index.html.j2",
            cases=[_case_summary(loaded) for loaded in store.all()],
            sources=upload_specs,
            accept=",".join(sorted({suffix for spec in upload_specs for suffix in spec.suffixes})),
            max_upload_kib=max_upload_bytes // 1024,
        )

    @app.get("/cases/{case_id}/timeline", response_class=HTMLResponse)
    def timeline(case_id: str) -> HTMLResponse:
        loaded = _require_case(case_id)
        model = build_report_model(loaded.case)
        events, capped = model.displayed_events(DEFAULT_HTML_MAX_EVENTS)
        return _render(
            "timeline.html.j2",
            case=_case_summary(loaded),
            stats=model.stats,
            attack=model.attack,
            events=events,
            capped=capped,
        )

    @app.get("/cases/{case_id}/report", response_class=HTMLResponse)
    def report(case_id: str) -> HTMLResponse:
        # The shared report layer renders the page: identical to the report the
        # command line writes for the same case.
        return HTMLResponse(render_html(_require_case(case_id).case))

    @app.post("/upload")
    async def upload(request: Request) -> Response:
        # The header gates run before the multipart body is parsed; only then is the
        # form read, with the server holding the body to its declared length. The
        # context manager closes the parsed parts (and deletes any spooled temp
        # file) when the handler exits, so a long-running viewer cannot leak file
        # descriptors or temp files across uploads.
        _enforce_upload_guards(request, max_upload_bytes)
        async with request.form() as form:
            spec = _upload_source(form.get("source"))
            file = form.get("file")
            if not isinstance(file, UploadFile):
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, detail="missing 'file' upload field"
                )
            text = await _read_upload(file, spec, max_upload_bytes)
            filename = file.filename or f"upload{spec.suffixes[0]}"

        case_id = store.next_upload_id()
        try:
            loaded = build_uploaded_case(case_id, spec.name, filename, text)
        except EmptyCaseError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"no events could be parsed from the upload as {spec.name} output: {exc}",
            ) from exc
        except (ValueError, csv.Error) as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"the upload could not be parsed as {spec.name} output",
            ) from exc
        store.put(loaded)
        return RedirectResponse(
            url=f"/cases/{case_id}/timeline", status_code=status.HTTP_303_SEE_OTHER
        )

    return app


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the viewer with uvicorn, bound to loopback by default.

    Loopback-only by default keeps the viewer local to the host, consistent with
    the offline, evidence-sovereign posture (Hard rule 2). uvicorn is imported
    lazily so importing this module pulls in no server machinery.
    """
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port)
