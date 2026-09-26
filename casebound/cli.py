"""The Casebound command line.

  - ``report``   : analyze your own evidence (one or more files, any mix of sources)
                   and write the reports.
  - ``demo``     : run the whole pipeline on the bundled synthetic intrusion,
                   offline, and check the published numbers.
  - ``verify``   : check claims drafted anywhere (another tool, another model, a
                   person) against a case's events.
  - ``sources``  : list the evidence sources Casebound reads.
  - ``generate`` : write the synthetic scenario's evidence and labels.
  - ``serve``    : open the optional local web viewer.

Exit codes: 0 on success, 1 when the run failed or a check did not pass (unreadable
evidence, no events, a rejected claim, a missed target), 2 for a usage or
configuration error.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

import typer

from casebound import __version__

if TYPE_CHECKING:
    from casebound.evaluation import Evaluation
    from casebound.pipeline import Case, EvidenceInput
    from casebound.report.writer import ReportPaths
    from casebound.verify.engine import NarrativeModel

app = typer.Typer(
    name="casebound",
    help=(
        "Casebound: DFIR timelines and investigation narratives in which every claim "
        "is verified against the evidence. Runs offline; models are optional."
    ),
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)

# File names the demo writes beside the reports.
METRICS_NAME = "metrics.json"

# How many unparsed-row reasons an error message lists before summarizing.
_PROBLEM_PREVIEW = 3


def _fail(message: str, code: int) -> NoReturn:
    """Print an error to stderr and exit with ``code``."""
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=code)


def _print_version(value: bool) -> None:
    """Eager --version callback: print the version and exit before any command."""
    if value:
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
    """Casebound: verification-fenced DFIR investigation reports."""


def _ensure_out_dir(out_dir: Path) -> None:
    """Create the output directory, failing cleanly when the path is blocked."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except (FileExistsError, NotADirectoryError, PermissionError) as exc:
        _fail(f"--out-dir {out_dir} is not a usable directory: {exc}", 2)


def _evidence_inputs(
    values: Sequence[str], source: str | None, column_map: Path | None
) -> list[EvidenceInput]:
    """Resolve the evidence arguments into inputs, validating every combination.

    Each value is a path when ``--source`` names the source for all of them, and
    ``SOURCE:PATH`` otherwise, so one run can mix sources.
    """
    from casebound.ingest.generic_csv import ColumnMap
    from casebound.pipeline import EvidenceInput
    from casebound.sources import SOURCES, UnknownSourceError, get_source

    loaded_map: ColumnMap | None = None
    inputs: list[EvidenceInput] = []
    for value in values:
        if source is not None:
            name, raw_path = source, value
        else:
            prefix, sep, rest = value.partition(":")
            if not sep or prefix.lower() not in SOURCES or not rest:
                _fail(
                    f"cannot tell which tool produced {value!r}: write it as SOURCE:PATH "
                    f"(for example hayabusa:{value}) or pass --source. Sources: "
                    f"{', '.join(SOURCES)}",
                    2,
                )
            name, raw_path = prefix.lower(), rest
        try:
            spec = get_source(name)
        except UnknownSourceError as exc:
            _fail(str(exc), 2)
        path = Path(raw_path)
        if not path.is_file():
            _fail(f"evidence file {raw_path!r} does not exist or is not a file", 2)
        item_map = None
        if spec.needs_column_map:
            if column_map is None:
                _fail(f"source {spec.name} needs --column-map (see docs/ingest-generic-csv.md)", 2)
            if loaded_map is None:
                try:
                    loaded_map = ColumnMap.from_json(column_map)
                except KeyError as exc:
                    _fail(f"column map {column_map} is missing the {exc.args[0]!r} key", 2)
                except (OSError, ValueError) as exc:
                    _fail(f"could not load column map {column_map}: {exc}", 2)
            item_map = loaded_map
        inputs.append(EvidenceInput(source=spec.name, path=path, column_map=item_map))
    if column_map is not None and not any(item.column_map for item in inputs):
        _fail("--column-map applies only to generic_csv evidence", 2)
    return inputs


def _model_label(model: NarrativeModel) -> str:
    """Name the narrative source for the report masthead, never leaking a key."""
    from casebound.narrate.llm import AnthropicProvider, LocalProvider, OpenAIProvider

    if isinstance(model, LocalProvider):
        return f"local model {model.model} at {model.base_url} (evidence stays on this host)"
    if isinstance(model, AnthropicProvider):
        return f"Anthropic {model.model} (cloud, redacted event views)"
    if isinstance(model, OpenAIProvider):
        return f"OpenAI {model.model} (cloud, redacted event views)"
    return "configured model"


def _run_pipeline(
    inputs: Sequence[EvidenceInput],
    *,
    name: str,
    model: NarrativeModel | None,
    model_label: str | None,
    max_rounds: int,
    view_budget: int | None,
) -> Case:
    """Run ``analyze`` and turn every expected failure into a clean exit."""
    from casebound.ingest.base import RawModeDependencyError
    from casebound.narrate.llm import ProviderConfigError, ProviderError
    from casebound.pipeline import EmptyCaseError, analyze
    from casebound.sources import UnknownSourceError

    try:
        return analyze(
            inputs,
            name=name,
            model=model,
            model_label=model_label,
            max_rounds=max_rounds,
            view_budget=view_budget,
        )
    except EmptyCaseError as exc:
        typer.echo(f"error: {exc}", err=True)
        for problem in exc.problems[:_PROBLEM_PREVIEW]:
            ref = problem.raw_ref
            typer.echo(f"  {ref.source_file}#{ref.record}: {problem.reason}", err=True)
        if len(exc.problems) > _PROBLEM_PREVIEW:
            typer.echo(f"  and {len(exc.problems) - _PROBLEM_PREVIEW} more", err=True)
        raise typer.Exit(code=1) from exc
    except (UnknownSourceError, RawModeDependencyError, ProviderConfigError) as exc:
        _fail(str(exc), 2)
    except ProviderError as exc:
        _fail(f"the narrative model failed: {exc} (rerun with --no-model for the report)", 1)
    except (OSError, UnicodeDecodeError, csv.Error, json.JSONDecodeError) as exc:
        # A file-level failure (a truncated JSON export, a binary blob, an oversized
        # CSV field): the per-row contract (FR7) lives in the normalize layer.
        _fail(f"failed reading the evidence: {exc}", 1)


def _print_case(case: Case, paths: ReportPaths) -> None:
    """Print the run summary shared by ``report`` and ``demo``."""
    for item in case.inputs:
        typer.echo(f"read {item.records} record(s) from {item.file} ({item.source})")
    typer.echo(f"normalized {len(case.events)} event(s)")
    if case.duplicate_count:
        typer.echo(f"collapsed {case.duplicate_count} duplicate record(s), provenance kept")
    if case.problems:
        typer.echo(f"reported {len(case.problems)} unparsed row(s) (listed in the report)")
    typer.echo(
        f"tagged {len(case.technique_ids())} ATT&CK technique(s), formed "
        f"{len(case.episodes)} episode(s), extracted {len(case.iocs)} indicator(s)"
    )
    if case.verification is None:
        typer.echo("no model: wrote the deterministic report (key findings, no narrative)")
    else:
        dropped = len(case.verification.dropped)
        typer.echo(
            f"narrative from {case.narrative_label}: {len(case.verification.accepted)} claim(s) "
            f"verified, {len(case.verification.audit)} rejection(s) logged, {dropped} dropped"
        )
    for path in paths.all():
        typer.echo(f"wrote {path}")


@app.command()
def report(
    evidence: list[str] = typer.Argument(
        ...,
        metavar="EVIDENCE...",
        help="Evidence files, as SOURCE:PATH (hayabusa:timeline.csv) or plain paths "
        "with --source. Run 'casebound sources' for the list.",
    ),
    source: str = typer.Option(
        None, "--source", "-s", help="The source of every evidence file given as a plain path."
    ),
    column_map: Path = typer.Option(
        None,
        "--column-map",
        "-m",
        help="Column-mapping JSON for generic_csv evidence (docs/ingest-generic-csv.md).",
    ),
    out_dir: Path = typer.Option(Path("out"), "--out-dir", "-o", help="Where to write reports."),
    name: str = typer.Option(
        None,
        "--name",
        "--case-name",
        "-n",
        help="Case name for the report. Defaults to the first evidence file's name.",
    ),
    no_model: bool = typer.Option(
        False, "--no-model", help="Skip the narrative even if a model is configured."
    ),
    allow_cloud: bool = typer.Option(
        False,
        "--allow-cloud",
        help="Consent to a configured cloud model. Event views are redacted first.",
    ),
    max_rounds: int = typer.Option(
        2, "--max-rounds", min=0, help="Revision rounds for rejected claims."
    ),
    view_budget: int = typer.Option(
        300,
        "--view-budget",
        min=1,
        help="Most events shown to the model (tagged and severe events first).",
    ),
    html_max_events: int = typer.Option(
        2000, "--html-max-events", min=1, help="Events shown in the HTML timeline."
    ),
) -> None:
    """Analyze your evidence and write the reports.

    Reads already-collected tool output (read-only), normalizes it into one
    timeline, tags ATT&CK, groups episodes, extracts indicators, and writes
    report.html, report.md, report.json, events.jsonl, and an ATT&CK Navigator
    layer. With no model configured the report is fully deterministic. Set
    CASEBOUND_PROVIDER=local for a verified narrative from a model on this host; a
    cloud model additionally needs --allow-cloud.
    """
    from casebound.narrate.llm import ProviderError, build_model_from_env
    from casebound.report import write_reports

    if no_model and allow_cloud:
        _fail("--no-model and --allow-cloud contradict each other; pick one", 2)
    inputs = _evidence_inputs(evidence, source, column_map)
    _ensure_out_dir(out_dir)

    model = None
    if not no_model:
        try:
            model = build_model_from_env(os.environ, allow_cloud=allow_cloud)
        except ProviderError as exc:
            _fail(str(exc), 2)

    default_name = inputs[0].path.stem
    if len(inputs) > 1:
        default_name += f" and {len(inputs) - 1} more"
    case = _run_pipeline(
        inputs,
        name=name or default_name,
        model=model,
        model_label=_model_label(model) if model is not None else None,
        max_rounds=max_rounds,
        view_budget=view_budget,
    )
    try:
        paths = write_reports(case, out_dir, html_max_events=html_max_events)
    except OSError as exc:
        _fail(f"failed writing the reports: {exc}", 1)
    _print_case(case, paths)


def _demo_model() -> tuple[NarrativeModel, str]:
    """The demo's narrator: a configured local model, else the offline narrator.

    The demo is the offline showcase, so it never uses a cloud provider, even when
    one is configured; it uses a local one only when an operator configured it.
    """
    from casebound.narrate import OfflineDemoNarrator
    from casebound.narrate.llm import LocalProvider, ProviderError, build_model_from_env

    try:
        configured = build_model_from_env(os.environ, allow_cloud=False)
    except ProviderError:
        configured = None
    if isinstance(configured, LocalProvider):
        return configured, _model_label(configured)
    return OfflineDemoNarrator(), OfflineDemoNarrator.LABEL


def _print_evaluation(evaluation: Evaluation) -> None:
    bench = evaluation.benchmark
    typer.echo("verifier benchmark:")
    typer.echo(
        f"  fabricated claims rejected: {bench.fabrications_rejected}/{bench.fabrications} "
        f"(false accepts: {len(bench.false_accepts)})"
    )
    typer.echo(
        f"  grounded claims accepted:   {bench.grounded_accepted}/{bench.grounded} "
        f"(false rejects: {len(bench.false_rejects)})"
    )
    typer.echo(
        f"  narrative citation accuracy: {evaluation.citation_accuracy:.2f} "
        f"({evaluation.accurate_claims}/{evaluation.emitted_claims})"
    )
    for label, score in (
        ("ATT&CK tagging, end to end", evaluation.attack_end_to_end),
        ("ATT&CK tagging, table only", evaluation.attack_table_only),
    ):
        if score is not None:
            typer.echo(
                f"{label}: precision {score.precision:.2f}, recall {score.recall:.2f} "
                f"({score.true_positives} correct, {score.false_positives} false positive(s), "
                f"{score.false_negatives} missed)"
            )


@app.command()
def demo(
    out_dir: Path = typer.Option(Path("out"), "--out-dir", "-o", help="Where to write outputs."),
    no_model: bool = typer.Option(
        False, "--no-model", help="Write the deterministic report, with no narrative."
    ),
) -> None:
    """Run the full pipeline on the bundled synthetic intrusion, offline.

    Regenerates the synthetic Hayabusa timeline, analyzes it, drafts a narrative
    with the offline demo narrator (or a configured local model) and verifies every
    claim, writes the reports, then runs the verifier benchmark and scores the
    ATT&CK tagging against the scenario's labels. Exits 1 if the verifier accepted
    a fabricated claim or rejected a grounded one.
    """
    from casebound.evaluation import evaluate
    from casebound.generate import write_samples
    from casebound.pipeline import EvidenceInput
    from casebound.report import write_reports

    _ensure_out_dir(out_dir)
    timeline, labels = write_samples(out_dir)
    ground_truth = json.loads(labels.read_text(encoding="utf-8"))

    model: NarrativeModel | None = None
    label: str | None = None
    if not no_model:
        model, label = _demo_model()
    case = _run_pipeline(
        [EvidenceInput(source="hayabusa", path=timeline)],
        name=str(ground_truth["scenario"]),
        model=model,
        model_label=label,
        max_rounds=2,
        view_budget=300,
    )
    paths = write_reports(case, out_dir)
    evaluation = evaluate(case, ground_truth)
    metrics_path = out_dir / METRICS_NAME
    metrics_path.write_text(
        json.dumps(evaluation.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    _print_case(case, paths)
    typer.echo(f"wrote {metrics_path}")
    _print_evaluation(evaluation)
    if not evaluation.passed:
        _fail("the verifier misjudged a benchmark claim (see metrics.json)", 1)
    typer.echo("verification guarantee held on every measured claim")


@app.command()
def verify(
    claims: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Claims to check: JSON in the documented claim format (docs/verification.md).",
    ),
    events: Path = typer.Option(
        ...,
        "--events",
        "-e",
        exists=True,
        dir_okay=False,
        readable=True,
        help="The case's events.jsonl, as written by 'casebound report'.",
    ),
    out: Path = typer.Option(None, "--out", "-o", help="Also write the results as JSON here."),
) -> None:
    """Check claims drafted anywhere against a case's events.

    Every claim must cite event ids from the case and assert the facts it states
    (datetime, principal, action, object) in its 'asserts' block. Each claim is
    accepted only if one cited event matches every asserted fact. Exits 0 when every
    claim is accepted and 1 when any is rejected.
    """
    from casebound.normalize.schema import Event
    from casebound.report.phrasing import phrase_event
    from casebound.verify.checks import verify_claim
    from casebound.verify.claims import ClaimParseError, parse_claims

    index: dict[str, Event] = {}
    try:
        with events.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    event = Event.from_dict(json.loads(line))
                except Exception as exc:  # any invalid line is a usage error
                    _fail(f"{events}:{number} is not a valid canonical event: {exc}", 2)
                index[event.event_id] = event
    except (OSError, UnicodeDecodeError) as exc:
        _fail(f"could not read {events}: {exc}", 2)
    if not index:
        _fail(f"{events} holds no events", 2)

    try:
        parsed = parse_claims(claims.read_text(encoding="utf-8"))
    except (ClaimParseError, OSError, UnicodeDecodeError) as exc:
        _fail(f"could not read claims from {claims}: {exc}", 2)
    if not parsed:
        _fail(f"{claims} holds no claims", 2)

    results = []
    rejected = 0
    for claim in parsed:
        verdict = verify_claim(claim, index)
        backing = index.get(verdict.backing_event_id or "")
        if verdict.ok and backing is not None:
            typer.echo(f"ACCEPT  {phrase_event(backing)} [{backing.event_id[:12]}]")
        else:
            rejected += 1
            reason = verdict.reason.value if verdict.reason else "rejected"
            typer.echo(f"REJECT  {claim.text}")
            typer.echo(f"        {reason}: {verdict.detail}")
        results.append(
            {
                "claim": claim.to_dict(),
                "verdict": verdict.to_dict(),
                "statement": phrase_event(backing) if verdict.ok and backing else None,
            }
        )
    typer.echo(
        f"{len(parsed) - rejected} of {len(parsed)} claim(s) verified against {len(index)} event(s)"
    )
    if out is not None:
        try:
            out.write_text(
                json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            _fail(f"could not write {out}: {exc}", 1)
        typer.echo(f"wrote {out}")
    if rejected:
        raise typer.Exit(code=1)


@app.command()
def sources() -> None:
    """List the evidence sources Casebound reads."""
    from casebound.sources import SOURCES

    width = max(len(name) for name in SOURCES)
    for spec in SOURCES.values():
        note = f' (needs: pip install "casebound[{spec.extra}]")' if spec.extra else ""
        if spec.needs_column_map:
            note = " (needs --column-map)"
        typer.echo(f"{spec.name.ljust(width)}  {spec.description}{note}")


@app.command()
def generate(
    out_dir: Path = typer.Option(
        Path("samples"), "--out-dir", "-o", help="Where to write the timeline and labels."
    ),
    seed: int = typer.Option(
        None, "--seed", "-s", help="Seed for cosmetic ids. Omit to reproduce the bundled samples."
    ),
) -> None:
    """Write the synthetic scenario's Hayabusa timeline and ground-truth labels."""
    from casebound.generate import DEFAULT_SEED, write_samples

    _ensure_out_dir(out_dir)
    timeline, labels = write_samples(out_dir, seed=DEFAULT_SEED if seed is None else seed)
    typer.echo(f"wrote {timeline}")
    typer.echo(f"wrote {labels}")


@app.command()
def serve(
    host: str = typer.Option(
        "127.0.0.1", "--host", help="Interface to bind (loopback by default)."
    ),
    port: int = typer.Option(8000, "--port", min=1, max=65535, help="Port to listen on."),
) -> None:
    """Open the optional local web viewer (needs the web extra)."""
    try:
        from casebound.web.app import serve as run_server
    except ImportError as exc:
        _fail(f'the web viewer needs its extra: pip install "casebound[web]" ({exc})', 2)
    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.echo(
            f"warning: binding {host} exposes the viewer beyond this host; "
            "evidence you upload will be reachable from the network",
            err=True,
        )
    run_server(host=host, port=port)


@app.command()
def version() -> None:
    """Print the Casebound version."""
    typer.echo(__version__)


if __name__ == "__main__":
    app()
