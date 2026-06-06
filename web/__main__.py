"""Run the Casebound web UI as ``python -m web``.

Starts the loopback server (PRD Section 8, decision D4). Offline and no-egress by
default; evidence never leaves the host.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from web.app import serve

if __name__ == "__main__":
    serve()
