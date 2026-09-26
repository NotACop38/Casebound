"""Detection severity, normalized across sources.

Detection tools grade what they flag: Hayabusa prints abbreviated levels (``crit``,
``high``, ``med``, ``low``, ``info``, ``emer``), Chainsaw and Sigma use the full
words. A source keeps its own spelling in ``details["level"]``; this module maps
any of them onto one ordered vocabulary so the pipeline can rank events (for the
model's event budget) and a report can compare them. An unrecognized or missing
level is None: severity is never invented.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from typing import Any

__all__ = ["SEVERITIES", "normalize_severity", "severity_rank"]

# The normalized severities, lowest first.
SEVERITIES: tuple[str, ...] = ("informational", "low", "medium", "high", "critical")

_ALIASES: dict[str, str] = {
    "info": "informational",
    "informational": "informational",
    "information": "informational",
    "low": "low",
    "med": "medium",
    "medium": "medium",
    "high": "high",
    "crit": "critical",
    "critical": "critical",
    # Hayabusa's "emergency" sits above critical; the normalized scale tops out
    # at critical, which keeps the ranking total without inventing a level.
    "emer": "critical",
    "emergency": "critical",
}


def normalize_severity(level: Any) -> str | None:
    """Return the normalized severity for a source's level string, or None."""
    if not isinstance(level, str):
        return None
    return _ALIASES.get(level.strip().casefold())


def severity_rank(severity: str | None) -> int:
    """Rank a normalized severity for sorting: higher is more severe, None is -1."""
    if severity is None:
        return -1
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return -1
