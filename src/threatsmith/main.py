"""CLI entry point for ThreatSmith."""

from __future__ import annotations

import logging
import os
import sys
from typing import Annotated

import typer

from threatsmith._install_skills import install_skills, list_skill_statuses
from threatsmith.engines import get_engine
from threatsmith.frameworks import get_framework, list_frameworks
from threatsmith.orchestrator import Orchestrator
from threatsmith.utils.logging import configure_logging
from threatsmith.utils.metadata import generate_metadata, write_metadata

logger = logging.getLogger(__name__)


app = typer.Typer(add_completion=False)
skills_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Manage ThreatSmith agent skills.",
)
app.add_typer(skills_app, name="skills")


_LOGO_LINES = [
    " ████████╗ ██╗  ██╗ ██████╗  ███████╗  █████╗  ████████╗ ███████╗ ███╗   ███╗ ██╗ ████████╗ ██╗  ██╗",
    " ╚══██╔══╝ ██║  ██║ ██╔══██╗ ██╔════╝ ██╔══██╗ ╚══██╔══╝ ██╔════╝ ████╗ ████║ ██║ ╚══██╔══╝ ██║  ██║",
    "    ██║    ███████║ ██████╔╝ █████╗   ███████║    ██║    ███████╗ ██╔████╔██║ ██║    ██║    ███████║",
    "    ██║    ██╔══██║ ██╔══██╗ ██╔══╝   ██╔══██║    ██║    ╚════██║ ██║╚██╔╝██║ ██║    ██║    ██╔══██║",
    "    ██║    ██║  ██║ ██║  ██║ ███████╗ ██║  ██║    ██║    ███████║ ██║ ╚═╝ ██║ ██║    ██║    ██║  ██║",
    "    ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝    ╚═╝    ╚══════╝ ╚═╝     ╚═╝ ╚═╝    ╚═╝    ╚═╝  ╚═╝",
]


def _print_logo() -> None:
    if not sys.stdout.isatty():
        for line in _LOGO_LINES:
            print(line)
        print()
        return

    # Fire gradient: top #ffb199 → bottom #ff0844
    top = (255, 177, 153)
    bot = (255, 8, 68)
    n = len(_LOGO_LINES) - 1
    reset = "\033[0m"
    print()
    for i, line in enumerate(_LOGO_LINES):
        t = i / n if n else 0
        r = round(top[0] + (bot[0] - top[0]) * t)
        g = round(top[1] + (bot[1] - top[1]) * t)
        b = round(top[2] + (bot[2] - top[2]) * t)
        print(f"\033[38;2;{r};{g};{b}m{line}{reset}")
    print()


def _load_config(path: str) -> dict:
    """Load .threatsmith.yml key-value config from the target directory."""
    config_path = os.path.join(path, ".threatsmith.yml")
    if not os.path.isfile(config_path):
        return {}
    config: dict = {}
    try:
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and ":" in line:
                    key, _, value = line.partition(":")
                    config[key.strip()] = value.strip()
    except OSError:
        pass
    return config


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    list_frameworks_flag: Annotated[
        bool,
        typer.Option(
            "--list-frameworks",
            help="List available frameworks and exit",
            is_eager=True,
        ),
    ] = False,
) -> None:
    """ThreatSmith — AI-powered threat modeling engine."""
    if list_frameworks_flag:
        print("Available frameworks:")
        for pack in list_frameworks():
            print(f"  {pack.name:<12} {pack.display_name} — {pack.description}")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        print(ctx.get_help())
        raise typer.Exit()


@app.command(no_args_is_help=True)
def model(
    path: Annotated[str, typer.Argument(help="Path to the target repository")],
    engine: Annotated[
        str,
        typer.Option(
            help="AI engine to use ('claude-code' or 'codex')", show_default=False
        ),
    ],
    framework: Annotated[
        str | None,
        typer.Option(help="Threat modeling framework to use", show_default="stride-4q"),
    ] = None,
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
    """Produce a threat model for a repository by driving the installed skill."""
    configure_logging(verbose)

    _print_logo()
    if not os.path.isdir(path):
        logger.error("Path does not exist or is not a directory: %s", path)
        raise SystemExit(1)

    # Load config file; CLI --framework takes precedence over config file
    config = _load_config(path)
    resolved_framework = framework or config.get("framework", "stride-4q")

    # Validate and resolve framework pack
    try:
        pack = get_framework(resolved_framework)
    except ValueError as exc:
        logger.error("%s", exc)
        raise SystemExit(1)

    # Resolve output directory (relative to target repo path)
    abs_output_dir = os.path.join(path, output_dir)
    os.makedirs(abs_output_dir, exist_ok=True)

    # Build user objectives dict
    user_objectives = {
        "business_objectives": business_objectives,
        "security_objectives": security_objectives,
    }

    # Run the pipeline
    logger.info("Starting %s pipeline for: %s", pack.display_name, path)
    engine_instance = get_engine(engine, verbose=verbose)
    orchestrator = Orchestrator(
        engine=engine_instance,
        repo_path=path,
        pack=pack,
        output_dir=output_dir,
        user_objectives=user_objectives,
    )
    exit_code = orchestrator.run()

    # Generate and write metadata after the pipeline so stages_completed is accurate
    metadata = generate_metadata(
        engine_name=engine,
        framework=pack,
        stages_completed=orchestrator.stages_completed,
        user_objectives={
            "business": business_objectives,
            "security": security_objectives,
        },
    )
    write_metadata(abs_output_dir, metadata)
    logger.debug("Metadata written to: %s", abs_output_dir)

    raise SystemExit(exit_code)


@skills_app.command("install", no_args_is_help=True)
def skills_install(
    engine: Annotated[
        str,
        typer.Option(
            help="AI engine whose skills directory to install into "
            "('claude-code' or 'codex')",
            show_default=False,
        ),
    ],
    verbose: Annotated[
        bool, typer.Option("-v", "--verbose", help="Enable verbose logging")
    ] = False,
) -> None:
    """Install (or refresh) the bundled ThreatSmith skills for the selected engine."""
    configure_logging(verbose)

    try:
        engine_instance = get_engine(engine, verbose=verbose)
    except ValueError as exc:
        logger.error("%s", exc)
        raise SystemExit(1)

    skills_dir = engine_instance.skills_dir
    try:
        installed = install_skills(skills_dir)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        raise SystemExit(1)

    for skill in installed:
        logger.info("Installed %s -> %s", skill.name, skill.destination)
    logger.info("Installed %d skill(s) into %s", len(installed), skills_dir)


@skills_app.command("list", no_args_is_help=True)
def skills_list(
    engine: Annotated[
        str,
        typer.Option(
            help="AI engine whose skills directory to check ('claude-code' or 'codex')",
            show_default=False,
        ),
    ],
) -> None:
    """List the bundled skills and whether they are installed for the engine."""
    configure_logging(False)

    try:
        engine_instance = get_engine(engine, verbose=False)
    except ValueError as exc:
        logger.error("%s", exc)
        raise SystemExit(1)

    skills_dir = engine_instance.skills_dir
    try:
        statuses = list_skill_statuses(skills_dir)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        raise SystemExit(1)

    print(f"Bundled skills (install target: {skills_dir}):")
    for status in statuses:
        marker = "installed" if status.installed else "not installed"
        print(f"  {status.name:<24} [{marker}]")
