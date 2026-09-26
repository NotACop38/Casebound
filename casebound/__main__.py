"""Run the Casebound command line as ``python -m casebound``.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from casebound.cli import app

if __name__ == "__main__":
    app(prog_name="casebound")
