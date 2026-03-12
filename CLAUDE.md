## Project Overview

ThreatSmith is an AI-powered PASTA (Process for Attack Simulation and Threat Analysis) threat modeling engine. It wraps AI coding agents (Claude Code, Codex) to orchestrate a rigorous 7-stage threat modeling pipeline, producing structured markdown deliverables including threat analysis, vulnerability assessment, attack trees, and risk prioritization.

## Technical Stack


## Development Commands

```bash
uv run pytest                # run all tests
uv run ruff check --fix      # lint (auto-fix; never manually fix lint issues)
uv run ruff format           # format (always use this, never manually reformat)
```

Always run `uv run ruff check --fix` and `uv run ruff format` to let the tools auto-fix issues. Do not run the check-only variants (`ruff check` without `--fix`, `ruff format --check`) and then manually apply fixes.

## Codebase Patterns
