"""IOC extraction and defanging (PRD FR16).

Extracts indicators of compromise (IPv4 addresses, domains, file hashes, and file
paths) from the normalized events into one structured, de-duplicated set, and
records on each event which indicators it references. No model is in this loop:
extraction is a pure function of the events' fields, so the same events always
yield the same indicators.

Where indicators are read from: an event's ``object`` plus its ``message`` and the
string values inside ``details`` (recursively). These are the normalized,
already-extracted fields, never a raw evidence file (Hard rule 4).

How a candidate string is classified, in order, so a value is never double-counted:

  1. A value that is wholly a Windows path (a drive-letter path such as
     ``C:\\Users\\...`` or a UNC path such as ``\\\\host\\share``) is taken as one
     path indicator. Taking the whole value first is what lets a path that
     contains spaces (``C:\\Program Files\\...``) survive intact.
  2. Otherwise the value is scanned for embedded indicators with the matched spans
     blanked as each kind is found, so an inner match cannot be re-read as another
     kind: drive-letter paths, then UNC paths, then hashes, then IPv4 addresses,
     then domains. Masking the paths first is what stops a path's trailing
     ``updater.exe`` from being misread as a domain.

Domain precision: a domain candidate whose final label is a known executable or
data-file extension (``exe``, ``dll``, and so on) is rejected, so a bare file name
in free text is not promoted to a domain. The check deliberately does not list any
real top-level domain, so a genuine ``host.com`` is still extracted.

Defanging renders a network indicator unclickable for safe handling and reporting:
an IP or domain has each dot bracketed (``1[.]2[.]3[.]4``, ``evil[.]example``) and
any ``http`` scheme rewritten to ``hxxp``. A hash or a path carries no
network-actionable content, so its defanged form is itself.

Each indicator gets a stable ``ioc-<short hash>`` id derived from its type and
normalized value, surfaced on every referencing event in ``ioc_refs``. Tagging
returns event copies; the core identity fields, and so every ``event_id``, are
unchanged (an indicator reference is addressing, not identity), and the operation
is idempotent.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

from casebound.normalize.schema import Event

__all__ = [
    "IOC_TYPE_DOMAIN",
    "IOC_TYPE_HASH",
    "IOC_TYPE_IP",
    "IOC_TYPE_PATH",
    "Ioc",
    "IocExtraction",
    "IocSet",
    "defang",
    "extract_iocs",
]

IOC_TYPE_IP = "ip"
IOC_TYPE_DOMAIN = "domain"
IOC_TYPE_HASH = "hash"
IOC_TYPE_PATH = "path"

# A stable, human-readable display order for the indicator types in a report.
_TYPE_ORDER = (IOC_TYPE_IP, IOC_TYPE_DOMAIN, IOC_TYPE_HASH, IOC_TYPE_PATH)

# Domain-separation prefix folded into the hashed identity of an indicator.
_IOC_ID_NAMESPACE = "casebound-ioc-v0.1"
_SHORT_ID_LEN = 12

# An MD5, SHA-1, or SHA-256 hex digest (32, 40, or 64 hex chars). The longest
# alternative is tried first so a 64-char digest is not clipped to its first 32.
_HASH_RE = re.compile(r"\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})\b")

# A dotted-quad IPv4 address with each octet bounded to 0 to 255.
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# A drive-letter path and a UNC path. Both stop at whitespace, quotes, the field
# separators a source uses, the redirection or pipe characters that bound a
# command-line argument, and the plus that prefixes a call-trace offset
# (ntdll.dll+9d2e4), so an embedded path is captured without its neighbours.
_PATH_STOP = r"\s\"'<>|¦,;+"
_DRIVE_PATH_RE = re.compile(rf"[A-Za-z]:\\[^{_PATH_STOP}]+")
_UNC_PATH_RE = re.compile(rf"\\\\[^{_PATH_STOP}]+")

# A hostname with at least one dot and an alphabetic top-level label.
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")

# Final labels that look like a domain TLD but are file extensions, so a bare file
# name in free text (``updater.exe``) is not promoted to a domain. None of these is
# a real TLD, so a genuine domain is never rejected by this list.
_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "dat",
        "bin",
        "tmp",
        "log",
        "txt",
        "scr",
        "bat",
        "cmd",
        "vbs",
        "msi",
        "lnk",
        "etl",
        "reg",
        "ini",
        "dmp",
        "pdb",
        "mui",
        "nls",
        "evtx",
    }
)


@dataclass(frozen=True)
class Ioc:
    """One extracted indicator of compromise.

    ``ioc_id`` is the stable ``ioc-<short hash>`` handle. ``ioc_type`` is one of the
    module's ``IOC_TYPE_*`` constants. ``value`` is the normalized indicator and
    ``defanged`` is its unclickable rendering. ``event_ids`` are the events that
    referenced it, in chronological-then-id order.
    """

    ioc_id: str
    ioc_type: str
    value: str
    defanged: str
    event_ids: tuple[str, ...]

    @property
    def event_count(self) -> int:
        """How many events reference this indicator."""
        return len(self.event_ids)

    def to_dict(self) -> dict[str, object]:
        """Render the indicator as a JSON-ready dict."""
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "defanged": self.defanged,
            "event_ids": list(self.event_ids),
        }


@dataclass(frozen=True)
class IocSet:
    """The structured set of indicators extracted from a run, in display order."""

    iocs: tuple[Ioc, ...] = ()

    def __iter__(self):  # type: ignore[no-untyped-def]
        return iter(self.iocs)

    def __len__(self) -> int:
        return len(self.iocs)

    def __bool__(self) -> bool:
        return bool(self.iocs)

    def by_type(self, ioc_type: str) -> list[Ioc]:
        """The indicators of one type, in display order."""
        return [ioc for ioc in self.iocs if ioc.ioc_type == ioc_type]

    def to_dict(self) -> dict[str, object]:
        """Render the set as a JSON-ready dict grouped by indicator type."""
        return {
            ioc_type: [ioc.to_dict() for ioc in self.by_type(ioc_type)] for ioc_type in _TYPE_ORDER
        }


@dataclass
class _Bucket:
    """Internal accumulator for one indicator while extracting: its id and refs."""

    ioc_id: str
    event_ids: list[str]


@dataclass
class IocExtraction:
    """The output of one extraction run.

    ``iocs`` is the structured indicator set. ``events`` are the input events, in
    their original order, each returned as a copy whose ``ioc_refs`` name the
    indicators it referenced.
    """

    iocs: IocSet = field(default_factory=IocSet)
    events: list[Event] = field(default_factory=list)


def defang(value: str, ioc_type: str) -> str:
    """Return the defanged rendering of an indicator.

    For an IP or a domain, every dot is bracketed so the value cannot be resolved
    by accident, and an actual ``http://`` or ``https://`` scheme prefix is
    rewritten to ``hxxp(s)://``. The scheme rewrite is anchored to a real prefix so
    a domain label that merely contains the letters http (for example
    ``httpbin.org``) is not corrupted. A hash or a path carries no
    network-actionable content, so it is returned unchanged.
    """
    if ioc_type not in (IOC_TYPE_IP, IOC_TYPE_DOMAIN):
        return value
    rendered = re.sub(r"(?i)^https://", "hxxps://", value)
    rendered = re.sub(r"(?i)^http://", "hxxp://", rendered)
    return rendered.replace(".", "[.]")


def _compute_ioc_id(ioc_type: str, value: str) -> str:
    """Return the stable ``ioc-<short hash>`` id for a typed, normalized value."""
    payload = "\n".join([_IOC_ID_NAMESPACE, ioc_type, value])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"ioc-{digest[:_SHORT_ID_LEN]}"


def _normalize_value(ioc_type: str, value: str) -> str:
    """Canonicalize an indicator for de-duplication.

    Domains and hashes are case-insensitive, so they are lowercased; an IP or a
    path is kept verbatim.
    """
    if ioc_type in (IOC_TYPE_DOMAIN, IOC_TYPE_HASH):
        return value.lower()
    return value


# A value that is one whole path: a drive-letter or UNC prefix followed only by
# path-shaped characters to the end of the string. Spaces are allowed (so
# ``C:\\Program Files\\...`` stays intact), but a colon, a forward slash, a plus, or
# the other characters below are not, so a value that merely starts with a path (a
# command line ``C:\\...\\curl.exe https://host`` or ``C:\\a.exe C:\\b.txt``, or a
# call trace ``C:\\...\\ntdll.dll+9d2e4``) does not match and falls through to the
# embedded scan, which extracts the leading path plus the URL, IP, or second path
# as separate indicators.
_WHOLE_PATH_BODY = "[^:/+,;¦'\"<>|?\n\r\t]*"
_WHOLE_PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\)" + _WHOLE_PATH_BODY + r"$")


def _is_whole_path(value: str) -> bool:
    """True when the entire value is a single drive-letter or UNC path."""
    return bool(_WHOLE_PATH_RE.match(value))


def _blank_spans(
    text: str,
    pattern: re.Pattern[str],
    found: list[tuple[str, str]],
    ioc_type: str,
) -> str:
    """Record every match of ``pattern`` as ``ioc_type`` and blank its span in ``text``."""
    chars = list(text)
    for match in pattern.finditer(text):
        found.append((ioc_type, match.group(0)))
        for index in range(match.start(), match.end()):
            chars[index] = " "
    return "".join(chars)


def _candidates_from_value(value: str) -> list[tuple[str, str]]:
    """Classify one source string into its (type, raw value) indicators."""
    stripped = value.strip()
    if not stripped:
        return []
    if _is_whole_path(stripped):
        return [(IOC_TYPE_PATH, stripped)]

    found: list[tuple[str, str]] = []
    work = stripped
    work = _blank_spans(work, _DRIVE_PATH_RE, found, IOC_TYPE_PATH)
    work = _blank_spans(work, _UNC_PATH_RE, found, IOC_TYPE_PATH)
    work = _blank_spans(work, _HASH_RE, found, IOC_TYPE_HASH)
    work = _blank_spans(work, _IPV4_RE, found, IOC_TYPE_IP)
    for match in _DOMAIN_RE.finditer(work):
        candidate = match.group(0)
        if candidate.rsplit(".", 1)[-1].lower() in _FILE_EXTENSIONS:
            continue
        found.append((IOC_TYPE_DOMAIN, candidate))
    return found


def _iter_strings(value: object) -> Iterable[str]:
    """Yield every string reachable inside a details value (recursively)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _event_strings(event: Event) -> list[str]:
    """The candidate strings an event contributes: object, message, and details."""
    strings: list[str] = []
    if event.object is not None:
        strings.append(event.object)
    strings.append(event.message)
    strings.extend(_iter_strings(event.details))
    return strings


def extract_iocs(events: Iterable[Event]) -> IocExtraction:
    """Extract indicators from events into a structured set and tag the events (FR16).

    Builds one de-duplicated ``IocSet`` from every event's object, message, and
    details, and returns each event as a copy whose ``ioc_refs`` name the
    indicators it referenced (idempotent: an already-present reference is not
    duplicated). The core identity fields, and so every ``event_id``, are unchanged.
    """
    materialized = list(events)

    # Accumulate, per (type, normalized value), the indicator id and the
    # referencing event ids in first-seen order.
    by_value: dict[tuple[str, str], _Bucket] = {}
    refs_by_event: dict[str, list[str]] = {}

    for event in materialized:
        seen_here: set[str] = set()
        for source in _event_strings(event):
            for ioc_type, raw in _candidates_from_value(source):
                normalized = _normalize_value(ioc_type, raw)
                key = (ioc_type, normalized)
                ioc_id = _compute_ioc_id(ioc_type, normalized)
                bucket = by_value.get(key)
                if bucket is None:
                    by_value[key] = _Bucket(ioc_id=ioc_id, event_ids=[event.event_id])
                elif event.event_id not in bucket.event_ids:
                    bucket.event_ids.append(event.event_id)
                if ioc_id not in seen_here:
                    seen_here.add(ioc_id)
                    refs_by_event.setdefault(event.event_id, []).append(ioc_id)

    order_index = {event.event_id: position for position, event in enumerate(materialized)}

    iocs: list[Ioc] = []
    for (ioc_type, normalized), bucket in by_value.items():
        ordered_ids = tuple(
            sorted(bucket.event_ids, key=lambda eid: order_index.get(eid, len(order_index)))
        )
        iocs.append(
            Ioc(
                ioc_id=bucket.ioc_id,
                ioc_type=ioc_type,
                value=normalized,
                defanged=defang(normalized, ioc_type),
                event_ids=ordered_ids,
            )
        )

    iocs.sort(key=lambda ioc: (_TYPE_ORDER.index(ioc.ioc_type), ioc.value))
    ioc_set = IocSet(tuple(iocs))

    tagged: list[Event] = []
    for event in materialized:
        refs = refs_by_event.get(event.event_id, [])
        additions = [ref for ref in sorted(refs) if ref not in event.ioc_refs]
        if not additions:
            tagged.append(event)
            continue
        tagged.append(replace(event, ioc_refs=[*event.ioc_refs, *additions]))

    return IocExtraction(iocs=ioc_set, events=tagged)
