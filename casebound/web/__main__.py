"""Run the Casebound web viewer as ``python -m casebound.web``.

Starts the loopback server (PRD Section 8, decision D4). Offline and no-egress by
default; evidence never leaves the host. ``casebound serve`` is the same server
with host and port options.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from casebound.web.app import serve

if __name__ == "__main__":
    serve()
