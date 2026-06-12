"""Casebound command-line interface.

This is the single command surface for the pipeline (PRD Section 8).

  - generate  : emit the synthetic ground-truth scenario (FR33).
  - demo      : run the full slice offline on the bundled synthetic scenario (FR34).
  - report    : run the full pipeline on the user's own evidence file.

The PRD sketched granular ingest, normalize, and analyze plumbing subcommands;
``report`` covers that whole chain in one step, which is what an analyst actually
wants (evidence in, verified report out). Plumbing subcommands can still land
later if a real workflow needs the intermediates.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from casebound.verify.engine import NarrativeModel

if TYPE_CHECKING:
    from casebound.ingest.base import IngestAdapter
    from casebound.metrics import Metrics
    from casebound.normalize.pipeline import NormalizationProblem

app = typer.Typer(
    name="casebound",
    help="Local-first DFIR investigation copilot with a verification-fenced narrative.",
    no_args_is_help=True,
    add_completion=False,
)

# The default output files the demo and report commands write. The HTML report is
# the hero deliverable; the JSON and Markdown carry the same content (FR29, FR30),
# the Navigator layer holds the observed techniques (FR31), and metrics.json
# persists the demo's headline numbers (PRD Section 12). README and Makefile
# reference these paths.
REPORT_HTML_NAME = "report.html"
REPORT_JSON_NAME = "report.json"
REPORT_MARKDOWN_NAME = "report.md"
NAVIGATOR_LAYER_NAME = "attack_navigator_layer.json"
METRICS_NAME = "metrics.json"


def _print_version(value: bool) -> None:
    """Eager --version callback: print the version and exit before any command."""
    if value:
        from casebound import __version__

        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Print the Casebound version and exit.",
        callback=_print_version,
        is_eager=True,
    ),
) -> None:
    """Casebound: a verification-fenced DFIR investigation copilot."""
    # Present so the CLI is a command group with room for future subcommands.


@app.command()
def version() -> None:
    """Print the Casebound version."""
    from casebound import __version__

    typer.echo(__version__)


def _ensure_out_dir(out_dir: Path) -> None:
    """Create the output directory, failing cleanly when the path is blocked.

    A pre-existing file at the path (or a file on the way to it) would otherwise
    surface as a raw traceback from ``mkdir`` deep inside the run.
    """
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError, PermissionError) as exc:
        typer.echo(f"error: --out-dir {out_dir} is not a usable directory: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def generate(
    out_dir: Path = typer.Option(
        Path("samples"),
        "--out-dir",
        "-o",
        help="Directory to write the synthetic CSV and ground-truth label file into.",
    ),
    seed: int | None = typer.Option(
        None,
        "--seed",
        "-s",
        help="Generation seed. Omit to use the pinned default for the bundled samples.",
    ),
) -> None:
    """Emit the synthetic ground-truth intrusion scenario (offline, FR33).

    Writes a Hayabusa-style CSV timeline plus a ground-truth label file. With no
    seed, it reproduces the bundled samples byte for byte.
    """
    from casebound.generate import DEFAULT_SEED, write_samples

    _ensure_out_dir(out_dir)
    chosen = DEFAULT_SEED if seed is None else seed
    csv_path, ground_truth_path = write_samples(out_dir, seed=chosen)
    typer.echo(f"wrote {csv_path}")
    typer.echo(f"wrote {ground_truth_path}")


@dataclass(frozen=True)
class DemoResult:
    """The outcome of one demo run, for the CLI summary and the tests.

    ``report_path`` is the self-contained HTML written; ``json_path``,
    ``markdown_path``, ``layer_path``, and ``metrics_path`` are the sibling outputs
    (the JSON and Markdown reports, the ATT&CK Navigator layer, and the persisted
    metrics). The counts summarize the deterministic pipeline and the verifier.
    ``metrics`` carries the headline numbers (PRD Section 12). ``no_model`` is True
    when the deterministic no-model path was taken (no narrative produced, FR26).
    """

    report_path: Path
    json_path: Path
    markdown_path: Path
    layer_path: Path
    metrics_path: Path
    event_count: int
    problem_count: int
    technique_count: int
    episode_count: int
    ioc_count: int
    accepted_count: int
    rejected_count: int
    metrics: Metrics
    no_model: bool


def _configured_model() -> NarrativeModel | None:
    """Return a configured local narrative model for the demo, or None (FR26, FR27).

    Provider selection lives in ``narrate.llm.build_model_from_env``; the narrative
    defaults to a local model so evidence never leaves the host (R8, FR27). The
    bundled demo is the offline showcase, so it deliberately uses only a local
    provider a user has explicitly configured through ``CASEBOUND_PROVIDER``, and
    never a cloud provider (that would send data off-host). With nothing configured
    this returns None and the demo takes the deterministic no-model path or the
    bundled offline narrator (FR26). No cloud call is ever made from the demo: cloud
    use goes through ``build_model_from_env`` with an explicit consent flag.
    """
    from casebound.narrate.llm import LocalProvider, ProviderError, build_model_from_env

    try:
        model = build_model_from_env(os.environ, allow_cloud=False)
    except ProviderError:
        return None
    return model if isinstance(model, LocalProvider) else None


def run_demo(
    out_dir: Path,
    *,
    model: NarrativeModel | None = None,
    model_label: str | None = None,
    max_rounds: int | None = None,
    seed: int | None = None,
) -> DemoResult:
    """Run the full Phase 1 slice offline and write the HTML report (FR34).

    Ingests the bundled synthetic Hayabusa scenario, normalizes it to the canonical
    schema, tags ATT&CK deterministically, runs the verifier when a ``model`` is
    supplied, and renders the self-contained HTML report to ``out_dir/report.html``.

    Fully offline with no API keys. When ``model`` is None, the no-model
    deterministic path is taken: the report carries the timeline, the tags, and the
    evidence appendix, and says no narrative was produced (FR26). When a model is
    supplied (a local provider, the bundled offline demo narrator, or the mocked
    model the tests use), the verified narrative and the rejected-claims audit are
    included. ``model_label`` names the narrative source in the report;
    ``max_rounds`` overrides the verifier's revision-round budget.
    """
    import json

    from casebound.enrich.attack import tag_events
    from casebound.enrich.cluster import cluster_events
    from casebound.enrich.ioc import extract_iocs
    from casebound.generate import DEFAULT_SEED, generate
    from casebound.generate.synth import CSV_FILENAME
    from casebound.ingest import HayabusaAdapter
    from casebound.metrics import compute_metrics
    from casebound.normalize import normalize_records
    from casebound.report import (
        write_json_report,
        write_markdown_report,
        write_navigator_layer,
        write_report,
    )
    from casebound.verify import DEFAULT_MAX_ROUNDS, verify_narrative

    out_dir.mkdir(parents=True, exist_ok=True)

    # Regenerate the bundled scenario deterministically so the demo is self-contained
    # from a clean clone: it does not depend on samples/ being present (FR34).
    chosen = DEFAULT_SEED if seed is None else seed
    scenario = generate(seed=chosen)
    csv_path = out_dir / CSV_FILENAME
    csv_path.write_text(scenario.csv_text, encoding="utf-8")

    normalized = normalize_records(HayabusaAdapter().read(csv_path))
    events = tag_events(normalized.events)

    # Enrich the tagged events into episodes and indicators (FR15, FR16). Each step
    # returns event copies carrying its tags or refs; the chain leaves both on every
    # event, and the report surfaces the episode list and the indicator set.
    clustered = cluster_events(events)
    extracted = extract_iocs(clustered.events)
    enriched_events = extracted.events

    rounds = DEFAULT_MAX_ROUNDS if max_rounds is None else max_rounds
    verification = (
        verify_narrative(enriched_events, model, max_rounds=rounds) if model is not None else None
    )
    resolved_label = None
    if model is not None:
        resolved_label = model_label if model_label is not None else "local model (offline)"

    scenario_name = scenario.ground_truth["scenario"]
    report_args = {
        "scenario": scenario_name,
        "source_tool": "hayabusa",
        "model_label": resolved_label,
        "provenance": normalized.provenance,
        "episodes": clustered.episodes,
        "iocs": extracted.iocs,
    }

    # The HTML report is the hero deliverable; the JSON and Markdown carry the same
    # content (FR29, FR30), and the Navigator layer holds the observed techniques
    # (FR31). All four regenerate offline from the same enriched events.
    report_path = write_report(
        out_dir / REPORT_HTML_NAME, enriched_events, verification, **report_args
    )
    json_path = write_json_report(
        out_dir / REPORT_JSON_NAME, enriched_events, verification, **report_args
    )
    markdown_path = write_markdown_report(
        out_dir / REPORT_MARKDOWN_NAME, enriched_events, verification, **report_args
    )
    layer_path = write_navigator_layer(
        out_dir / NAVIGATOR_LAYER_NAME, enriched_events, scenario=scenario_name
    )

    # Compute and persist the headline metrics (PRD Section 12, FR35).
    metrics = compute_metrics(enriched_events, verification, scenario.ground_truth)
    metrics_path = out_dir / METRICS_NAME
    metrics_path.write_text(
        json.dumps(metrics.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    technique_count = len(
        {tech.technique_id for event in enriched_events for tech in event.attack_techniques}
    )
    return DemoResult(
        report_path=report_path,
        json_path=json_path,
        markdown_path=markdown_path,
        layer_path=layer_path,
        metrics_path=metrics_path,
        event_count=len(enriched_events),
        problem_count=normalized.problem_count,
        technique_count=technique_count,
        episode_count=len(clustered.episodes),
        ioc_count=len(extracted.iocs),
        accepted_count=len(verification.accepted) if verification else 0,
        rejected_count=len(verification.audit) if verification else 0,
        metrics=metrics,
        no_model=model is None,
    )


@app.command()
def demo(
    out_dir: Path = typer.Option(
        Path("out"),
        "--out-dir",
        "-o",
        help="Directory to write the report and regenerated evidence into.",
    ),
    no_model: bool = typer.Option(
        False,
        "--no-model",
        help="Emit the deterministic report with no narrative, the no-model path (FR26).",
    ),
) -> None:
    """Run the full pipeline on the bundled synthetic scenario, offline (FR34).

    Ingests, normalizes, tags ATT&CK, drafts and verifies the narrative, and writes
    a self-contained HTML report to ``out-dir/report.html``. Runs with no API keys.

    A configured local model drafts the narrative; with none configured the bundled
    offline demo narrator drafts it instead, so the verifier still runs and the
    report carries a verified narrative and a rejected-claims audit, fully offline.
    Pass ``--no-model`` to take the deterministic no-model path, which emits the
    timeline, tags, and appendix with no narrative (FR26).
    """
    from casebound.narrate import OfflineDemoNarrator

    _ensure_out_dir(out_dir)
    used_demo_narrator = False
    if no_model:
        result = run_demo(out_dir, model=None)
    else:
        configured = _configured_model()
        if configured is not None:
            result = run_demo(out_dir, model=configured)
        else:
            # No real provider is wired yet, so the bundled offline narrator drafts
            # the narrative in a single verification pass for a clean audit.
            used_demo_narrator = True
            result = run_demo(
                out_dir,
                model=OfflineDemoNarrator(),
                model_label=OfflineDemoNarrator.LABEL,
                max_rounds=0,
            )

    typer.echo(f"ingested and normalized {result.event_count} events")
    if result.problem_count:
        typer.echo(f"reported {result.problem_count} malformed row(s) without aborting")
    typer.echo(f"tagged {result.technique_count} distinct ATT&CK technique(s)")
    typer.echo(
        f"clustered {result.episode_count} activity episode(s) and "
        f"extracted {result.ioc_count} indicator(s)"
    )
    if result.no_model:
        typer.echo("no language model configured: wrote the deterministic report (no narrative)")
    else:
        if used_demo_narrator:
            typer.echo(
                "no language model configured: drafted the narrative with the bundled "
                "offline demo narrator (no network, no LLM)"
            )
        typer.echo(
            f"verified narrative: {result.accepted_count} claim(s) accepted, "
            f"{result.rejected_count} rejected and logged"
        )

    metrics = result.metrics
    attack = metrics.attack
    typer.echo("metrics (PRD Section 12):")
    typer.echo(
        f"  hallucination-rejection rate: {metrics.hallucination_rejection_rate:.2f} "
        f"({metrics.rejected_fabrications}/{metrics.seeded_fabrications} seeded fabrications "
        "rejected, target 1.00)"
    )
    typer.echo(
        f"  citation accuracy: {metrics.citation_accuracy:.2f} "
        f"({metrics.accurate_claims}/{metrics.emitted_claims} emitted claims, target 1.00)"
    )
    typer.echo(
        f"  ATT&CK precision: {attack.precision:.2f} (target 0.90), "
        f"recall: {attack.recall:.2f} (target 0.70)"
    )
    typer.echo(f"  technique coverage: {metrics.coverage} distinct technique(s)")
    typer.echo(f"  targets met: {'yes' if metrics.meets_targets() else 'no'}")

    typer.echo(f"wrote {result.report_path}")
    typer.echo(f"wrote {result.json_path}")
    typer.echo(f"wrote {result.markdown_path}")
    typer.echo(f"wrote {result.layer_path}")
    typer.echo(f"wrote {result.metrics_path}")

    # The demo is a reproducibility check: if any headline metric falls below its
    # PRD Section 12 target, fail loudly rather than writing the outputs and exiting
    # 0, so a regressed verifier or tagger cannot be reproduced as a green run.
    if not metrics.meets_targets():
        typer.echo("error: one or more metrics fell below target (see above)", err=True)
        raise typer.Exit(code=1)


class EvidenceSource(StrEnum):
    """The tool whose output ``casebound report`` ingests (one adapter per source).

    Values match the canonical ``source_tool`` tokens (PRD Section 10). The raw
    Dissect adapters are deliberately absent: they live in the license-gated
    ``casebound.ingest.raw`` subpackage, which the core CLI never imports (D2).
    """

    hayabusa = "hayabusa"
    eztools = "eztools"
    chainsaw = "chainsaw"
    velociraptor = "velociraptor"
    plaso = "plaso"
    generic_csv = "generic_csv"


class ReportUsageError(ValueError):
    """The report command was invoked with an unusable source or column map."""


class EmptyTimelineError(RuntimeError):
    """The evidence yielded no canonical events, so there is nothing to report.

    Almost always a wrong ``--source`` for the file (every row failed to
    normalize) or an empty export. ``problems`` carries the per-row reasons so
    the command can show the user why nothing parsed.
    """

    def __init__(self, source: str, problems: list[NormalizationProblem]) -> None:
        super().__init__(
            f"no events could be normalized from the evidence as source '{source}' "
            f"({len(problems)} row(s) failed); is --source right for this file?"
        )
        self.problems = problems


@dataclass(frozen=True)
class ReportResult:
    """The outcome of one report run, for the CLI summary and the tests.

    Mirrors ``DemoResult`` minus the metrics: user evidence has no ground-truth
    labels, so the demo-only evaluation numbers (PRD Section 12) do not apply.
    ``duplicate_count`` says how many source rows collapsed into an already-seen
    event (FR12); their provenance is retained in the report appendix.
    """

    report_path: Path
    json_path: Path
    markdown_path: Path
    layer_path: Path
    event_count: int
    problem_count: int
    duplicate_count: int
    technique_count: int
    episode_count: int
    ioc_count: int
    accepted_count: int
    rejected_count: int
    no_model: bool


def _build_adapter(source: str, column_map: Path | None) -> IngestAdapter:
    """Build the ingest adapter for a source, validating the column-map usage.

    ``generic_csv`` requires a column-mapping config (the analyst must say which
    columns hold the canonical fields, docs/ingest-generic-csv.md); every other
    source has a bespoke adapter and takes no config.
    """
    from casebound.ingest import (
        ChainsawAdapter,
        ColumnMap,
        EZToolsAdapter,
        GenericCsvAdapter,
        HayabusaAdapter,
        PlasoAdapter,
        VelociraptorAdapter,
    )

    if source == EvidenceSource.generic_csv.value:
        if column_map is None:
            raise ReportUsageError(
                "--source generic_csv requires --column-map pointing at the "
                "column-mapping JSON (see docs/ingest-generic-csv.md)"
            )
        try:
            mapping = ColumnMap.from_json(column_map)
        except KeyError as exc:
            raise ReportUsageError(
                f"column map {column_map} is missing the required {exc.args[0]!r} key"
            ) from exc
        except (OSError, ValueError) as exc:
            raise ReportUsageError(f"could not load column map {column_map}: {exc}") from exc
        return GenericCsvAdapter(mapping)

    if column_map is not None:
        raise ReportUsageError("--column-map applies only to --source generic_csv")

    adapters: dict[str, type[IngestAdapter]] = {
        EvidenceSource.hayabusa.value: HayabusaAdapter,
        EvidenceSource.eztools.value: EZToolsAdapter,
        EvidenceSource.chainsaw.value: ChainsawAdapter,
        EvidenceSource.velociraptor.value: VelociraptorAdapter,
        EvidenceSource.plaso.value: PlasoAdapter,
    }
    return adapters[source]()


def _model_label_for(model: NarrativeModel) -> str:
    """Name the narrative source for the report masthead, never leaking a key."""
    from casebound.narrate.llm import AnthropicProvider, LocalProvider, OpenAIProvider

    if isinstance(model, LocalProvider):
        return f"local model ({model.model}, on host)"
    if isinstance(model, (AnthropicProvider, OpenAIProvider)):
        provider = "anthropic" if isinstance(model, AnthropicProvider) else "openai"
        return f"{provider} cloud model ({model.model}, redacted views)"
    return "configured model"


def run_report(
    evidence: Path,
    source: str,
    out_dir: Path,
    *,
    column_map: Path | None = None,
    case_name: str | None = None,
    model: NarrativeModel | None = None,
    model_label: str | None = None,
    max_rounds: int | None = None,
) -> ReportResult:
    """Run the full pipeline on a user evidence file and write the reports.

    Ingests ``evidence`` with the adapter for ``source``, normalizes to the
    canonical schema, tags ATT&CK, clusters episodes, extracts IOCs, runs the
    verifier when a ``model`` is supplied (FR17 to FR25), and writes the HTML,
    JSON, and Markdown reports plus the Navigator layer to ``out_dir``. With no
    model the deterministic no-model path is taken (FR26). Unlike the demo, no
    metrics file is written: user evidence carries no ground-truth labels.

    Raises ``ReportUsageError`` for a bad source and column-map combination and
    ``EmptyTimelineError`` when no row normalizes into an event (nothing is
    written in either case).
    """
    from casebound.enrich.attack import tag_events
    from casebound.enrich.cluster import cluster_events
    from casebound.enrich.ioc import extract_iocs
    from casebound.normalize import normalize_records
    from casebound.report import (
        write_json_report,
        write_markdown_report,
        write_navigator_layer,
        write_report,
    )
    from casebound.verify import DEFAULT_MAX_ROUNDS, verify_narrative

    adapter = _build_adapter(source, column_map)
    normalized = normalize_records(adapter.read(evidence))
    if not normalized.events:
        raise EmptyTimelineError(source, normalized.problems)

    events = tag_events(normalized.events)
    clustered = cluster_events(events)
    extracted = extract_iocs(clustered.events)
    enriched_events = extracted.events

    rounds = DEFAULT_MAX_ROUNDS if max_rounds is None else max_rounds
    verification = (
        verify_narrative(enriched_events, model, max_rounds=rounds) if model is not None else None
    )
    resolved_label = None
    if model is not None:
        resolved_label = model_label if model_label is not None else _model_label_for(model)

    case_label = case_name if case_name else evidence.stem
    report_args: dict[str, Any] = {
        "scenario": case_label,
        "source_tool": source,
        "model_label": resolved_label,
        "provenance": normalized.provenance,
        "episodes": clustered.episodes,
        "iocs": extracted.iocs,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = write_report(
        out_dir / REPORT_HTML_NAME, enriched_events, verification, **report_args
    )
    json_path = write_json_report(
        out_dir / REPORT_JSON_NAME, enriched_events, verification, **report_args
    )
    markdown_path = write_markdown_report(
        out_dir / REPORT_MARKDOWN_NAME, enriched_events, verification, **report_args
    )
    layer_path = write_navigator_layer(
        out_dir / NAVIGATOR_LAYER_NAME, enriched_events, scenario=case_label
    )

    technique_count = len(
        {tech.technique_id for event in enriched_events for tech in event.attack_techniques}
    )
    return ReportResult(
        report_path=report_path,
        json_path=json_path,
        markdown_path=markdown_path,
        layer_path=layer_path,
        event_count=len(enriched_events),
        problem_count=normalized.problem_count,
        duplicate_count=normalized.duplicate_count,
        technique_count=technique_count,
        episode_count=len(clustered.episodes),
        ioc_count=len(extracted.iocs),
        accepted_count=len(verification.accepted) if verification else 0,
        rejected_count=len(verification.audit) if verification else 0,
        no_model=model is None,
    )


@app.command()
def report(
    evidence: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="The evidence file to analyze: already-collected tool output (CSV or JSON timeline).",
    ),
    source: EvidenceSource = typer.Option(
        ...,
        "--source",
        "-s",
        case_sensitive=False,
        help="The tool that produced the evidence file.",
    ),
    column_map: Path = typer.Option(
        None,
        "--column-map",
        "-m",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Column-mapping JSON for --source generic_csv (see docs/ingest-generic-csv.md).",
    ),
    out_dir: Path = typer.Option(
        Path("out"),
        "--out-dir",
        "-o",
        help="Directory to write the reports and the Navigator layer into.",
    ),
    case_name: str = typer.Option(
        None,
        "--case-name",
        "-n",
        help="Case label shown in the report masthead. Defaults to the evidence file name.",
    ),
    no_model: bool = typer.Option(
        False,
        "--no-model",
        help="Skip the narrative even if a provider is configured: the deterministic "
        "report only (FR26).",
    ),
    allow_cloud: bool = typer.Option(
        False,
        "--allow-cloud",
        help="Consent to a configured cloud provider (FR27). Event views are redacted "
        "before any cloud call; without this flag a cloud provider is refused.",
    ),
    max_rounds: int = typer.Option(
        None,
        "--max-rounds",
        min=0,
        help="Verifier revision-round budget for rejected claims (default 2, FR23).",
    ),
) -> None:
    """Run the full pipeline on your own evidence and write the verified report.

    Ingests already-collected tool output (read-only, Hard rule 1), builds the
    normalized timeline, tags ATT&CK, clusters episodes, extracts IOCs, and writes
    the HTML, JSON, and Markdown reports plus the ATT&CK Navigator layer.

    The narrative layer is optional and local-first (FR26, FR27): with no provider
    configured the report is fully deterministic with no narrative. Set
    CASEBOUND_PROVIDER=local for an on-host model; a cloud provider additionally
    requires the explicit --allow-cloud consent and is always preceded by the
    redaction pass.
    """
    from casebound.narrate.llm import ProviderError, build_model_from_env

    if no_model and allow_cloud:
        typer.echo("error: --no-model and --allow-cloud contradict each other; pick one", err=True)
        raise typer.Exit(code=2)

    _ensure_out_dir(out_dir)

    model: NarrativeModel | None = None
    if not no_model:
        try:
            model = build_model_from_env(os.environ, allow_cloud=allow_cloud)
        except ProviderError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc

    try:
        result = run_report(
            evidence,
            source.value,
            out_dir,
            column_map=column_map,
            case_name=case_name,
            model=model,
            max_rounds=max_rounds,
        )
    except ReportUsageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except EmptyTimelineError as exc:
        typer.echo(f"error: {exc}", err=True)
        for problem in exc.problems[:3]:
            ref = problem.raw_ref
            typer.echo(f"  {ref.source_file}#{ref.record}: {problem.reason}", err=True)
        if len(exc.problems) > 3:
            typer.echo(f"  ... and {len(exc.problems) - 3} more row(s)", err=True)
        raise typer.Exit(code=1) from exc
    except ProviderError as exc:
        # A provider can fail lazily, from the first draft call: most commonly a
        # configured provider whose optional SDK package is not installed.
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except (OSError, UnicodeDecodeError, csv.Error, json.JSONDecodeError) as exc:
        # A file-level failure while reading the evidence or writing the outputs:
        # a truncated or non-JSON Chainsaw export, a binary blob, an oversized
        # CSV field, an unwritable output file. The per-row FR7 contract lives in
        # the normalize layer; this turns whole-file failures into a clean error.
        typer.echo(f"error: failed processing {evidence} as {source.value}: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    typer.echo(f"ingested {evidence} as {source.value}: {result.event_count} event(s)")
    if result.duplicate_count:
        typer.echo(f"collapsed {result.duplicate_count} duplicate record(s), provenance retained")
    if result.problem_count:
        typer.echo(f"reported {result.problem_count} malformed row(s) without aborting")
    typer.echo(f"tagged {result.technique_count} distinct ATT&CK technique(s)")
    typer.echo(
        f"clustered {result.episode_count} activity episode(s) and "
        f"extracted {result.ioc_count} indicator(s)"
    )
    if result.no_model:
        typer.echo(
            "no language model configured: wrote the deterministic report "
            "(set CASEBOUND_PROVIDER to add a verified narrative)"
        )
    else:
        typer.echo(
            f"verified narrative: {result.accepted_count} claim(s) accepted, "
            f"{result.rejected_count} rejected and logged"
        )

    typer.echo(f"wrote {result.report_path}")
    typer.echo(f"wrote {result.json_path}")
    typer.echo(f"wrote {result.markdown_path}")
    typer.echo(f"wrote {result.layer_path}")


if __name__ == "__main__":
    app()
