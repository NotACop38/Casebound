"""Lazy, isolated Dissect imports for raw mode (decision D2).

Every import of the AGPL-licensed Dissect happens here, inside a function, never
at module load. This is the single chokepoint that keeps Dissect off the core
import graph: the adapters call ``load_evtx_class`` or ``load_mft_class`` only when
a user actually invokes raw parsing, and a missing dependency surfaces as a clear,
actionable ``RawModeDependencyError`` rather than a bare ``ImportError`` deep in a
stack trace. Tests substitute these loaders to exercise the adapters offline.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from typing import Any

__all__ = ["RawModeDependencyError", "load_evtx_class", "load_mft_class"]

# How to obtain the optional dependency, named in every error so the fix is one
# copy-paste away. Dissect is intentionally not a core dependency (decision D2).
_INSTALL_HINT = 'install the optional raw extra: pip install "casebound[raw]"'


class RawModeDependencyError(ImportError):
    """Raised when raw-mode parsing is invoked without Dissect installed.

    Subclasses ``ImportError`` so callers can catch it naturally. The message
    names the optional extra to install.
    """


def load_evtx_class() -> Any:
    """Return the Dissect ``Evtx`` class, or raise ``RawModeDependencyError``."""
    try:
        from dissect.eventlog.evtx import Evtx
    except ImportError as exc:
        raise RawModeDependencyError(
            "raw EVTX parsing needs Dissect (dissect.eventlog), which is not "
            f"installed; {_INSTALL_HINT}"
        ) from exc
    return Evtx


def load_mft_class() -> Any:
    """Return the Dissect ``Mft`` class, or raise ``RawModeDependencyError``."""
    try:
        from dissect.ntfs.mft import Mft
    except ImportError as exc:
        raise RawModeDependencyError(
            f"raw MFT parsing needs Dissect (dissect.ntfs), which is not installed; {_INSTALL_HINT}"
        ) from exc
    return Mft
