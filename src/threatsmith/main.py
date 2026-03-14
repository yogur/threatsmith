"""CLI entry point for ThreatSmith."""

from __future__ import annotations

import os
from typing import Annotated

import typer

from threatsmith.engines import get_engine
from threatsmith.orchestrator import Orchestrator
from threatsmith.utils.metadata import generate_metadata, write_metadata
from threatsmith.utils.scanners import detect_scanners

app = typer.Typer(add_completion=False)


@app.command()
def main(
    path: Annotated[str, typer.Argument(help="Path to the target repository")],
    engine: Annotated[
        str, typer.Option(help="AI engine to use ('claude-code' or 'codex')")
    ] = "claude-code",
    business_objectives: Annotated[
        str | None,
        typer.Option(help="Optional business objectives to inject into the analysis"),
    ] = None,
    security_objectives: Annotated[
        str | None,
        typer.Option(help="Optional security objectives to inject into the analysis"),
    ] = None,
    output_dir: Annotated[
        str, typer.Option(help="Output directory for threat model deliverables")
    ] = "threatmodel/",
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Enable verbose logging")
    ] = False,
) -> None:
    """Run ThreatSmith PASTA threat modeling pipeline against a repository."""
    # Resolve output directory (relative to target repo path)
    abs_output_dir = os.path.join(path, output_dir)
    os.makedirs(abs_output_dir, exist_ok=True)

    # Detect available scanners
    scanner_info = detect_scanners()

    # Build user objectives dict
    user_objectives = {
        "business_objectives": business_objectives,
        "security_objectives": security_objectives,
    }

    # Generate and write metadata before starting the pipeline
    combined_objectives = " | ".join(
        o for o in [business_objectives, security_objectives] if o
    )
    metadata = generate_metadata(
        engine_name=engine,
        scanners_available=scanner_info["available"],
        scanners_unavailable=scanner_info["unavailable"],
        user_objectives=combined_objectives,
    )
    write_metadata(abs_output_dir, metadata)

    commit_hash = metadata.get("commit_hash")

    # Run the pipeline
    engine_instance = get_engine(engine)
    orchestrator = Orchestrator(
        engine=engine_instance,
        repo_path=path,
        output_dir=output_dir,
        scanner_info=scanner_info,
        user_objectives=user_objectives,
        commit_hash=commit_hash,
        verbose=verbose,
    )
    raise SystemExit(orchestrator.run())
