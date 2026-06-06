"""Casebound command-line interface.

This is the single command surface for the pipeline (PRD Section 8). Subcommands
are added as the modules they drive land, one checklist step at a time.

  - generate  : emit the synthetic ground-truth scenario (FR33).
  - demo      : run the full slice offline on the bundled synthetic scenario (FR34).

TODO(Phase 3+): the granular subcommands (ingest, normalize, analyze, report) as
  the breadth phases land; the demo already runs the whole slice end to end.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import typer

from casebound.verify.engine import NarrativeModel

app = typer.Typer(
    name="casebound",
    help="Local-first DFIR investigation copilot with a verification-fenced narrative.",
    no_args_is_help=True,
    add_completion=False,
)

# The default output file the demo writes (the hero deliverable). README and
# Makefile reference this path.
DEMO_REPORT_NAME = "report.html"


@app.callback()
def main() -> None:
    """Casebound: a verification-fenced DFIR investigation copilot."""
    # Present so the CLI is a command group with room for future subcommands.


@app.command()
def version() -> None:
    """Print the Casebound version."""
    from casebound import __version__

    typer.echo(__version__)


@app.command()
def generate(
    out_dir: Path = typer.Option(
        Path("samples"),
        "--out-dir",
        "-o",
        help="Directory to write the synthetic CSV and ground-truth label file into.",
    ),
    seed: int = typer.Option(
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

    chosen = DEFAULT_SEED if seed is None else seed
    csv_path, ground_truth_path = write_samples(out_dir, seed=chosen)
    typer.echo(f"wrote {csv_path}")
    typer.echo(f"wrote {ground_truth_path}")


@dataclass(frozen=True)
class DemoResult:
    """The outcome of one demo run, for the CLI summary and the tests.

    ``report_path`` is the self-contained HTML written. The counts summarize the
    deterministic pipeline and the verifier. ``no_model`` is True when the
    deterministic no-model path was taken (no narrative produced, FR26).
    """

    report_path: Path
    event_count: int
    problem_count: int
    technique_count: int
    episode_count: int
    ioc_count: int
    accepted_count: int
    rejected_count: int
    no_model: bool


def _configured_model() -> NarrativeModel | None:
    """Return the configured local narrative model, or None when none is set.

    The narrative defaults to a local model so evidence never leaves the host (R8,
    FR27); a cloud provider is opt-in only and out of scope here. No local provider
    is wired yet (that interface lands in Phase 5), so this returns None today and
    the demo takes the deterministic no-model path (FR26). The seam exists so the
    demo gains a verified narrative the moment a provider lands, with no change to
    the orchestration below.
    """
    return None


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
    from casebound.enrich.attack import tag_events
    from casebound.enrich.cluster import cluster_events
    from casebound.enrich.ioc import extract_iocs
    from casebound.generate import DEFAULT_SEED, generate
    from casebound.generate.synth import CSV_FILENAME
    from casebound.ingest import HayabusaAdapter
    from casebound.normalize import normalize_records
    from casebound.report import write_report
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

    report_path = write_report(
        out_dir / DEMO_REPORT_NAME,
        enriched_events,
        verification,
        scenario=scenario.ground_truth["scenario"],
        source_tool="hayabusa",
        model_label=resolved_label,
        provenance=normalized.provenance,
        episodes=clustered.episodes,
        iocs=extracted.iocs,
    )

    technique_count = len(
        {tech.technique_id for event in enriched_events for tech in event.attack_techniques}
    )
    return DemoResult(
        report_path=report_path,
        event_count=len(enriched_events),
        problem_count=normalized.problem_count,
        technique_count=technique_count,
        episode_count=len(clustered.episodes),
        ioc_count=len(extracted.iocs),
        accepted_count=len(verification.accepted) if verification else 0,
        rejected_count=len(verification.audit) if verification else 0,
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
    typer.echo(f"wrote {result.report_path}")


if __name__ == "__main__":
    app()
