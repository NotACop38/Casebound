# Casebound web UI (optional, Phase 9)

A minimal FastAPI viewer to load a case, browse the timeline, and read the report
in a browser. It is the opt-in stretch feature (PRD decision D4): the deterministic
core and the CLI do not depend on it, and a default install pulls in no web
framework.

The viewer reuses the report layer unchanged. The report it serves for the bundled
demo case is byte for byte the report `casebound demo` writes, because both render
through the same `casebound.report` functions. The web layer only assembles a case;
it never decides what a report says (AGENTS.md prime directive).

## Run it

The server dependencies live in the opt-in `web` extra, off the default import
graph:

```bash
pip install -e ".[web]"   # FastAPI, uvicorn, python-multipart
python -m web             # or: make web
```

It serves on `http://127.0.0.1:8000` by default. Pages:

- `/` the loaded cases and the upload form.
- `/cases/demo/timeline` browse the bundled scenario timeline.
- `/cases/demo/report` the full self-contained HTML report.
- `POST /upload` load your own Hayabusa CSV timeline.

## Offline and no-egress

- The server binds to loopback (`127.0.0.1`) only by default.
- It imports no HTTP client and opens no outbound socket; it fetches nothing.
- The report and timeline are self-contained: no asset is fetched at view time.
- Evidence never leaves the host. Any narrative defaults to the local, offline path.

## Upload hardening

An upload is gated on its headers before the body is even parsed, and is only ever
read as text:

- A browser-issued cross-site POST is refused (403) via fetch metadata and the
  Origin header, so a hostile page in your browser cannot drive uploads at the
  loopback server.
- The request must declare a Content-Length within the cap (5 MiB by default,
  plus multipart framing overhead), or it is rejected (411 or 413) before the
  multipart parser receives a single body byte; the HTTP server holds the body
  to its declared length.
- The filename must be a `.csv` and the content type must be a text or CSV type, or
  it is rejected (415).
- The file part itself is then read against the exact byte cap and rejected past it
  (413).
- The bytes must decode as UTF-8; binary content is rejected (415).
- The upload is parsed read-only as a Hayabusa CSV timeline. It is never opened as a
  program, executed, or fetched from anywhere, and no path or URL the client sends is
  ever dereferenced.
- An upload that yields no events is rejected (422) rather than rendered.

An uploaded timeline takes the deterministic no-model path: it is normalized,
tagged, clustered, and rendered with no narrative, since the scripted demo narrator
is specific to the bundled scenario.

## Layout

- `app.py` the FastAPI app (`create_app`), routes, upload hardening, and `serve`.
- `case.py` case assembly that reuses the pipeline and the unchanged report layer.
- `templates/` the index and timeline templates (autoescaped, self-contained).
