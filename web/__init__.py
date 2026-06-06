"""Optional web UI for Casebound (PRD Section 8, decision D4, Phase 9).

A minimal FastAPI app that loads a case, browses the timeline, and views the
report, reusing the existing report layer unchanged. This is the opt-in stretch
viewer: the deterministic core and the CLI do not depend on it, and its server
dependencies live in the ``web`` optional extra, off the default import graph.

Run it from a clone with ``python -m web`` (or ``web.app.serve``). It binds to
loopback by default and makes no outbound network call; evidence never leaves the
host (Hard rule 2).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from web.app import create_app, serve

__all__ = ["create_app", "serve"]
