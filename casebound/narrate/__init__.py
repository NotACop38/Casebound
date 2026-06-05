"""Narration: the provider-agnostic model interface and the drafting loop.

Calls a model to draft a narrative as a sequence of id-cited claims, then submits
rejected claims back for revision (FR23). The provider is abstracted behind one
interface (Anthropic, OpenAI, local), defaulting to local so evidence never leaves
the host by default (R8, FR27). The model only ever sees the compact, id-addressed
event view, never raw evidence files (Hard rule 4).

Planned layout (PRD Section 13): llm.py, loop.py, prompts/.

TODO(Phase 5): implement the provider interface and the no-model path.
"""

from __future__ import annotations
