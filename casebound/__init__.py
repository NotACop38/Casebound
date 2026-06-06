"""Casebound: a local-first DFIR investigation copilot.

Casebound ingests already-collected host triage output, normalizes every event
into one canonical timeline, deterministically maps activity to MITRE ATT&CK, and
produces an analyst-ready narrative in which every factual claim is verified
against a real timeline event or rejected before the analyst sees it.

The deterministic layer is the source of truth. The language model is a drafting
aid that is fenced by the verifier and never has the authority to state a fact.

See docs/PRD.md and docs/ENGINEERING_CHECKLIST.md for the full contract.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
