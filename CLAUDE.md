## Project Overview

ThreatSmith is an AI-powered PASTA (Process for Attack Simulation and Threat Analysis) threat modeling engine. It wraps AI coding agents (Claude Code, Codex) to orchestrate a 7-stage threat modeling pipeline plus a report consolidation step, producing structured markdown deliverables.

## Technical Stack

- Python 3.12+, src layout with hatchling build backend
- Typer for CLI, stdlib logging for all output
- No runtime dependencies beyond typer — engines are invoked via subprocess

## Development Commands

```bash
uv run pytest                # run all tests
uv run ruff check --fix      # lint (auto-fix; never manually fix lint issues)
uv run ruff format           # format (always use this, never manually reformat)
```

Always run `uv run ruff check --fix` and `uv run ruff format` to let the tools auto-fix issues. Do not run the check-only variants (`ruff check` without `--fix`, `ruff format --check`) and then manually apply fixes.

## Architecture

```
CLI (main.py)
  → detect_scanners(), generate_metadata()
  → Orchestrator.run()
      → for stage 1–8:
          assemble_prompt(stage_number, prior_outputs, scanner_info, ...)
            → selects stage module → builds typed context dataclass → calls build_prompt()
          engine.execute(prompt, working_directory) → exit_code
          validate output file exists → read into prior_outputs
```

### Key interfaces

- **Engine** (`engines/base.py`): ABC with `execute(prompt: str, working_directory: str) -> int`. Engines are thin subprocess wrappers — prompt assembly is the orchestrator's job.
- **`get_engine(name)`** (`engines/__init__.py`): Factory mapping `"claude-code"` / `"codex"` to engine classes.
- **`assemble_prompt()`** (`prompts/assembler.py`): Maps stage number to the correct stage module, builds the typed context dataclass, calls `build_prompt()`. Returns a single prompt string.
- **Stage prompt modules** (`prompts/stage_01_objectives.py` through `stage_08_report.py`): Each exports `STAGE_PROMPT` constant + `build_prompt(context, output_dir="threatmodel") -> str`.
- **Context dataclasses** (`prompts/contexts.py`): One per stage (e.g. `ObjectivesContext`, `VulnerabilityContext`). Fields are `str | None = None`; `VulnerabilityContext` also has `scanners_available: list[str] | None`.
- **Orchestrator** (`orchestrator.py`): Dataclass. `run()` iterates stages 1–8, accumulates deliverables in `_prior_outputs` dict keyed as `stage_01_output` through `stage_08_output`. Returns 0 on success, 1 on failure.

### Dynamic injection

- **OWASP references** (Stage 4): Web Top 10 always injected. API/LLM/Mobile Top 10 conditionally injected based on case-insensitive keyword matching against Stage 2 output. Constants in `prompts/references/owasp.py`.
- **Scanner snippets** (Stage 5): Injected per available scanner from `prompts/references/scanner_snippets.py` `SCANNER_SNIPPETS` dict. `detect_scanners()` returns `{"available": [...], "unavailable": [...]}`.

### Stage → file mapping

Defined in `orchestrator._STAGE_FILES`:
- `01-objectives.md` through `07-risk-and-impact-analysis.md` (PASTA stages)
- `08-report.md` (consolidation, not a PASTA stage — no new analysis)

## Package Structure

- **`__init__.py` files must stay thin** — re-exports only, no implementation code. Put logic in named modules (e.g. `conditions.py`, `models.py`) and re-export from `__init__.py` via explicit `from module import X` + `__all__`. This applies to all packages in the codebase.

## Codebase Patterns

- **Prompt placeholders**: Use `.replace("{placeholder}", value)`, not `.format()` — prompt text contains curly braces that break `.format()`.
- **Prior stage injection**: XML-delimited `<prior_stages><stage_NN_name>...</stage_NN_name></prior_stages>` via `{prior_stages_section}` placeholder. Each stage output is independently optional (only included when present).
- **`or None` guards**: `context.field or None` treats both missing and empty-string values as absent. Used throughout `build_prompt()` and `assemble_prompt()`.
- **Logging**: Modules use `logger = logging.getLogger(__name__)`. CLI configures via `configure_logging(verbose)` in `utils/logging.py`. DEBUG = verbose, INFO = operational progress, WARNING/ERROR = failures.
- **scanner_info keys**: `detect_scanners()` returns `{"available": [...], "unavailable": [...]}`. The assembler maps `scanner_info["available"]` to `VulnerabilityContext.scanners_available`.
- **metadata.json**: `generate_metadata()` accepts `engine_name` param but writes `"engine"` key. Returns a `Metadata` dataclass. `write_metadata(output_dir, metadata)` serializes to JSON.

## Testing Patterns

- Tests are in `tests/` at root level. Test files mirror source: `test_stage_04.py` tests `stage_04_threat_analysis.py`.
- Do not write tests for string constants — test logic and behavior only.
- **Mock engine in E2E tests**: Use a closure over `output_dir` in `execute_side_effect(prompt, working_directory)` to write stage files. Track call count with `{"n": 0}` dict.
- **Patch location for CLI tests**: Patch `threatsmith.main.get_engine` (not `threatsmith.engines.get_engine`) since the CLI imports into its own namespace.
- `detect_scanners()` and `generate_metadata()` are safe to use unpatched in tests — scanners uses `shutil.which()`, metadata falls back to `"unknown"` for git failures.
- Test logging with `caplog.at_level(logging.DEBUG, logger="threatsmith.module_name")`.
