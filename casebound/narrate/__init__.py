"""Narration: the provider-agnostic model interface and the drafting loop.

Calls a model to draft a narrative as a sequence of id-cited claims, then submits
rejected claims back for revision (FR23). The provider is abstracted behind one
interface (Anthropic, OpenAI, local), defaulting to local so evidence never leaves
the host by default (R8, FR27). The model only ever sees the compact, id-addressed
event view, never raw evidence files (Hard rule 4).

Layout (PRD Section 13): llm.py, loop.py, prompts/ for the real provider interface
(Phase 5). For now this module ships one offline, scripted drafter:

  - ``demo`` : ``OfflineDemoNarrator``, a deterministic, network-free stand-in the
    bundled demo uses so the verifier runs and the report carries a verified
    narrative and a rejected-claims audit, with no model configured and no keys.

TODO(Phase 5): implement the provider-agnostic interface (Anthropic, OpenAI,
  local) defaulting to local, and the redaction pass for any cloud path.
"""

from __future__ import annotations

from casebound.narrate.demo import OfflineDemoNarrator

__all__ = ["OfflineDemoNarrator"]
