"""The optional local web viewer (PRD Section 8, decision D4).

A minimal FastAPI app that lists cases, browses a case's timeline, and serves its
report, built on the same pipeline and report layer as the command line. The
deterministic core and the CLI do not depend on it, and its dependencies live in
the ``web`` extra (``pip install 'casebound[web]'``), so a default install imports
no web framework.

Start it with ``casebound serve`` (or ``python -m casebound.web``). It binds to
loopback by default and makes no outbound network call; evidence never leaves the
host (Hard rule 2).

This package init imports nothing from the server stack, so importing
``casebound.web`` never requires the extra; ``casebound.web.app`` does.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations
