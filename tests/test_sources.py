"""Tests for the evidence-source registry (``casebound.sources``).

Every entry point resolves a source name through this one table, so it must be
consistent with the schema vocabulary and the adapters, strict about unknown names
and column maps, and lazy about the license-gated raw adapters.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from casebound.ingest.base import RawModeDependencyError
from casebound.ingest.generic_csv import ColumnMap
from casebound.normalize.schema import SOURCE_TOOLS
from casebound.sources import (
    SOURCES,
    UnknownSourceError,
    build_adapter,
    get_source,
    source_names,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def test_registry_is_consistent_with_the_schema_vocabulary() -> None:
    assert source_names() == tuple(SOURCES)
    for spec in SOURCES.values():
        assert spec.tool in SOURCE_TOOLS, spec.name
        assert all(suffix.startswith(".") and suffix == suffix.lower() for suffix in spec.suffixes)
        assert spec.description


def test_lookup_is_case_and_space_insensitive() -> None:
    assert get_source("  HayaBusa ").name == "hayabusa"


def test_unknown_source_lists_the_known_ones() -> None:
    with pytest.raises(UnknownSourceError) as excinfo:
        get_source("splunk")
    for name in SOURCES:
        assert name in str(excinfo.value)


@pytest.mark.parametrize(
    "name", [name for name, spec in SOURCES.items() if not spec.extra and not spec.needs_column_map]
)
def test_tool_output_adapters_match_their_spec(name: str) -> None:
    adapter = build_adapter(name)
    assert adapter.source_tool == get_source(name).tool


def test_generic_csv_needs_a_column_map_and_nothing_else_takes_one() -> None:
    column_map = ColumnMap.from_json(FIXTURES / "generic_edr_map.json")
    assert build_adapter("generic_csv", column_map=column_map).source_tool == "generic_csv"
    with pytest.raises(UnknownSourceError, match="needs a column map"):
        build_adapter("generic_csv")
    with pytest.raises(UnknownSourceError, match="applies only to generic_csv"):
        build_adapter("hayabusa", column_map=column_map)


@pytest.mark.parametrize("name", ["evtx", "mft"])
def test_raw_sources_build_lazily_and_name_the_extra(name: str, tmp_path: Path) -> None:
    spec = get_source(name)
    assert spec.extra == "raw"
    adapter = build_adapter(name)
    assert adapter.source_tool == "dissect"
    try:
        import dissect  # noqa: F401
    except ImportError:
        artifact = tmp_path / "artifact.bin"
        artifact.write_bytes(b"\x00" * 16)
        with pytest.raises(RawModeDependencyError, match=r'pip install "casebound\[raw\]"'):
            list(adapter.read(artifact))
