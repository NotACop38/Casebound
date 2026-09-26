# The web viewer (optional)

A small local web app for browsing cases: a list of loaded cases, a timeline page
per case, and the full report. It is optional (PRD decision D4): the deterministic
core and the CLI do not depend on it, and a default install pulls in no web
framework.

It is a viewer, not a second pipeline. Every case is built by
`casebound.pipeline.analyze` and every report by `casebound.report.render_html`, so
the report the viewer serves for the bundled demo case is byte for byte the
`report.html` that `casebound demo` writes (a test holds it to that).

## Run it

```bash
pip install "casebound[web]"      # FastAPI, uvicorn, python-multipart
casebound serve                   # http://127.0.0.1:8000
casebound serve --port 9000       # another port
```

`python -m casebound.web` starts the same server. Binding anything other than
loopback prints a warning: the viewer has no authentication, so uploaded evidence
would be reachable from the network.

| Route | What it serves |
| --- | --- |
| `GET /` | The loaded cases and the upload form. |
| `GET /cases/{id}/timeline` | The case's events with host, principal, action, object, severity, and ATT&CK techniques. A case over 2000 events lists the notable ones and says so. |
| `GET /cases/{id}/report` | The self-contained HTML report. |
| `POST /upload` | Analyze one uploaded file and redirect to its timeline. |

The store starts with the bundled demo case, narrated by the offline demo narrator
and verified. It holds 16 cases by default and evicts the oldest upload first; the
demo case is never evicted.

## Uploads

An upload names its source and carries one file. The viewer accepts the
tool-output sources that need no extra configuration:

| Source | File types |
| --- | --- |
| `hayabusa` | `.csv`, `.json`, `.jsonl` |
| `chainsaw` | `.json` |
| `eztools` | `.csv` |
| `velociraptor` | `.jsonl`, `.json` |
| `plaso` | `.csv` |

Raw `.evtx` and `$MFT` artifacts (binary, and license-gated), generic CSV (needs a
column map), and model narratives are command-line features. An uploaded file
takes the deterministic path: normalized, tagged, clustered, and rendered with key
findings and no narrative.

## Hardening

The upload gates run on the headers before the body is parsed:

- A browser-issued cross-site or same-site POST, or one whose Origin names another
  host, is refused with 403, so a hostile page in the analyst's browser cannot
  drive uploads at the loopback server.
- The request must declare a Content-Length (411 without one, 400 if it is not a
  number) no larger than the cap, 5 MiB by default plus a small allowance for
  multipart framing (413). The HTTP server holds the body to its declared length,
  so the parser never receives more.

Then the file part:

- The form must name an accepted source (400).
- The file name's suffix must be one the source arrives as, and the content type
  must be a text or JSON type or one browsers send for unknown files (415).
- The part is read in chunks against the exact byte cap (413) and must decode as
  UTF-8 (415).
- It is parsed read-only by the source's adapter. A file that parses to no events,
  or cannot be parsed as that source at all, is refused with 422 and nothing is
  stored.

Nothing uploaded is executed, no path or URL from the request or the evidence is
ever opened or fetched, and the file is written only to a private temporary
directory that is removed as soon as it is parsed. The client-supplied file name is
reduced to a base name and used only as the provenance label.

## Offline

The viewer binds to loopback by default, imports no HTTP client, and opens no
outbound connection; its pages fetch nothing at view time. `tests/test_no_egress.py`
runs it with outbound sockets blocked.

## Layout

- `casebound/web/app.py`: the FastAPI app (`create_app`), the routes, the upload
  gates, the bounded case store, and `serve`.
- `casebound/web/case.py`: case assembly on the shared pipeline (the demo case and
  uploads) and upload-name sanitizing.
- `casebound/web/templates/`: the index and timeline pages (autoescaped,
  self-contained).
