"""Casebound command-line interface.

This is the single command surface for the pipeline (PRD Section 8). Subcommands
are added as the modules they drive land, one checklist step at a time.

TODO(Phase 1+): wire the real subcommands:
  - ingest    : parse tool output into raw, provenance-bearing records.
  - normalize : map records to the canonical event schema (PRD Section 10).
  - analyze   : enrich (ATT&CK tags, episodes, IOCs) and run the verifier.
  - report    : render the self-contained HTML report plus JSON and Markdown.
  - demo      : run the full slice offline on the bundled synthetic scenario.
  - generate  : emit the synthetic ground-truth scenario.
"""

from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(
    name="casebound",
    help="Local-first DFIR investigation copilot with a verification-fenced narrative.",
    no_args_is_help=True,
    add_completion=False,
)


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


if __name__ == "__main__":
    app()
