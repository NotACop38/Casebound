"""Optional raw-artifact ingestion via Dissect (PRD Section 5 Raw mode, D2).

Most of Casebound consumes tool output a responder already produced. This
subpackage is the exception: it parses raw evidence artifacts directly (a Windows
EVTX event log, an NTFS ``$MFT``) for users who have not pre-run the tools. It
does so with Dissect (Fox-IT, NCC Group).

License boundary (decision D2)
------------------------------
Dissect is licensed AGPL-3.0; the Casebound core is Apache-2.0. To keep the core
license permissive, this is the ONE place in the codebase that depends on Dissect,
and the dependency is isolated three ways:

  1. Optional install. Dissect is not a core dependency. It is declared only under
     the ``raw`` optional-dependency group (see ``pyproject.toml``). A default
     ``pip install casebound`` pulls in no AGPL code. Raw mode is opt-in:
     ``pip install "casebound[raw]"``.
  2. Lazy import. Nothing here imports Dissect at module load (see ``_loader``).
     The import happens inside ``read`` at the moment a user invokes raw parsing,
     so importing this subpackage never loads AGPL code.
  3. No core import path. No module outside ``casebound/ingest/raw`` imports this
     subpackage or Dissect. The core pipeline (ingest of tool output, normalize,
     enrich, verify, narrate, report, the demo) runs with zero AGPL code on its
     import graph. ``tests/test_license_boundary.py`` enforces this in code.

Because of (3), the normalization of the records these adapters emit lives in the
Apache-2.0 core (``casebound/normalize/mappers/dissect.py``) and is fully tested
offline with golden fixtures; only the thin Dissect-facing parsing lives here.

When you install the ``raw`` extra and use these adapters, the resulting combined,
installed work includes AGPL-3.0 code (Dissect) and is then subject to its terms.
Casebound itself neither bundles nor redistributes Dissect.

Defensive scope is unchanged: Dissect is a read-only parser of already-collected
artifacts. These adapters open evidence files read-only, never acquire, never
collect remotely, and never execute anything (Hard rule 1).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from casebound.ingest.raw._loader import RawModeDependencyError
from casebound.ingest.raw.evtx import DissectEvtxAdapter
from casebound.ingest.raw.mft import DissectMftAdapter

__all__ = ["DissectEvtxAdapter", "DissectMftAdapter", "RawModeDependencyError"]
