## Project Overview

ThreatSmith is an AI-powered threat modeling engine supporting multiple methodologies (PASTA, 4QF+STRIDE, LINDDUN Pro, MAESTRO) via a pluggable framework pack architecture. It wraps AI coding agents (Claude Code, Codex) to orchestrate a multi-stage threat modeling pipeline plus a report consolidation step, producing structured markdown deliverables.

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
  → pack = get_framework("pasta")
  → Orchestrator(engine, repo_path, pack, ...).run()
      → for stage in pack.stages + [pack.report_stage]:
          assemble_prompt(stage, pack, prior_outputs, scanner_info, ...)
            → evaluates pack.reference_sets → builds StageContext → calls stage.build_prompt(context, output_dir)
          engine.execute(prompt, working_directory) → exit_code
          validate output file exists → read into prior_outputs
```

### Key interfaces

- **Engine** (`engines/base.py`): ABC with `execute(prompt: str, working_directory: str) -> int`. Engines are thin subprocess wrappers — prompt assembly is the orchestrator's job.
- **`get_engine(name)`** (`engines/__init__.py`): Factory mapping `"claude-code"` / `"codex"` to engine classes.
- **`assemble_prompt()`** (`assembler.py` — top-level module): Framework-agnostic. Accepts `StageSpec` + `FrameworkPack`, evaluates reference conditions, builds `StageContext`, calls `stage.build_prompt(context, output_dir)`. Returns a single prompt string.
- **Stage prompt modules** (`frameworks/pasta/stage_01_objectives.py` through `frameworks/pasta/stage_08_report.py`): Each exports `STAGE_PROMPT` constant + `build_prompt(context: StageContext, output_dir="threatmodel") -> str`.
- **`StageContext`** (`frameworks/types.py`): Generic dataclass passed to all `build_prompt` functions. Fields: `user_objectives` (dict | None), `prior_outputs` (dict[str, str]), `scanners_available` (list[str] | None), `references` (list[str]).
- **`FrameworkPack` / `StageSpec`** (`frameworks/types.py`): Define framework structure — stages, output files, scanner stages, reference sets.
- **Orchestrator** (`orchestrator.py`): Framework-agnostic dataclass. Accepts `pack: FrameworkPack`. `run()` iterates `pack.stages + [pack.report_stage]`, accumulates deliverables in `_prior_outputs` dict keyed as `stage_01_output` through `stage_NN_output`. Returns 0 on success, 1 on failure.

### Dynamic injection

- **Reference injection** (assembler-driven): The assembler evaluates `pack.reference_sets[stage.number]` via `evaluate_reference_conditions()` against prior outputs. Resolved reference strings are passed to `build_prompt` via `context.references`. For PASTA stage 4: Web Top 10 always, API/LLM Top 10 conditional on keyword detection.
- **Scanner snippets** (assembler-driven): The assembler checks `stage.number in pack.scanner_stages`. If true, `context.scanners_available` is populated from `scanner_info["available"]`. Stage `build_prompt` functions look up scanner snippets from `SCANNER_SNIPPETS` dict in `frameworks/references/scanner_snippets.py`.

### Import graph (no circular dependencies)

```
frameworks/types.py           ← pure dataclasses + registry (no threatsmith imports)
frameworks/__init__.py        ← imports types.py; imports _built_in.py (side-effect registration)
frameworks/_built_in.py       ← imports pack builders from frameworks.pasta, etc.
frameworks/pasta/_pack.py     ← imports frameworks.types (sibling), frameworks.pasta.stage_XX, frameworks.references.owasp
frameworks/references/*       ← pure constants + utility (no threatsmith imports)
assembler.py                  ← imports frameworks.types, frameworks.references
orchestrator.py               ← imports assembler, engines.base
main.py                       ← imports frameworks, orchestrator, engines, utils
```

Pack builders import from `frameworks.types` directly (sibling module), not from `frameworks/__init__`. This keeps the import graph a DAG with no cycles.

## Package Structure

- **`__init__.py` files must stay thin** — re-exports only, no implementation code. Put logic in named modules (e.g. `conditions.py`, `types.py`, `_pack.py`) and re-export from `__init__.py` via explicit `from module import X` + `__all__`. This applies to all packages in the codebase.

## Codebase Patterns

- **Prompt placeholders**: Use `.replace("{placeholder}", value)`, not `.format()` — prompt text contains curly braces that break `.format()`.
- **Prior stage injection**: XML-delimited `<prior_stages><stage_NN_name>...</stage_NN_name></prior_stages>` via `{prior_stages_section}` placeholder. Each stage output is independently optional (only included when present).
- **`or None` guards**: `context.prior_outputs.get("stage_01_output") or None` treats both missing and empty-string values as absent. Used throughout `build_prompt()`.
- **User objectives access**: `objectives = context.user_objectives or {}; business = objectives.get("business_objectives") or None`.
- **References access**: `context.references` is a `list[str]` of pre-resolved reference strings, populated by the assembler from `pack.reference_sets`.
- **Logging**: Modules use `logger = logging.getLogger(__name__)`. CLI configures via `configure_logging(verbose)` in `utils/logging.py`. DEBUG = verbose, INFO = operational progress, WARNING/ERROR = failures.
- **scanner_info keys**: `detect_scanners()` returns `{"available": [...], "unavailable": [...]}`. The assembler maps `scanner_info["available"]` to `StageContext.scanners_available`.
- **metadata.json**: `generate_metadata()` accepts `engine_name` param but writes `"engine"` key. Returns a `Metadata` dataclass. `write_metadata(output_dir, metadata)` serializes to JSON.

## Testing Patterns

- Tests are in `tests/` at root level. PASTA stage tests live in `tests/pasta/` (e.g. `tests/pasta/test_stage_04.py` tests `frameworks/pasta/stage_04_threat_analysis.py`). Framework-specific tests for other frameworks follow the same pattern: `tests/<framework>/`.
- Do not write tests for string constants — test logic and behavior only.
- **Mock engine in E2E tests**: Use a closure over `output_dir` in `execute_side_effect(prompt, working_directory)` to write stage files. Track call count with `{"n": 0}` dict.
- **Patch location for CLI tests**: Patch `threatsmith.main.get_engine` and `threatsmith.main.get_framework` (not the module-level imports) since the CLI imports into its own namespace.
- `detect_scanners()` and `generate_metadata()` are safe to use unpatched in tests — scanners uses `shutil.which()`, metadata falls back to `"unknown"` for git failures.
- Test logging with `caplog.at_level(logging.DEBUG, logger="threatsmith.module_name")`.
