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


if __name__ == "__main__":
    app()
