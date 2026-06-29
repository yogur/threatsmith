> [!NOTE]
> **Architecture in transition (v0.4.0 — "Threat Modeling as Agent Skills").** The skills
> rewrite is the live design. Sprints 1–3 have landed: methodology prompts now live in
> distributable Agent Skills (the source of truth), the CLI drives *installed* skills per
> stage (Model B) passing prior context by file pointer, framework packs are thin
> orchestration metadata, and CLI-side reference conditions + scanner detection are gone.
> Built skills are bundled as package data (US-010) and the CLI now exposes subcommands —
> `threatsmith model <path>` runs a threat model and `threatsmith skills install` installs
> the bundled skills into the selected engine's skills directory (US-011). Pre-run skill
> validation exits with an actionable error if the required skill is missing (US-012), and
> `model --mode` selects `from-code` (default) or `from-docs` (`pair` is rejected as
> skill-only) with the mode recorded in `metadata.json` (US-013).
> **Still pending (sprint 5, US-014…US-017):** E2E coverage and docs. See `tasks/threatsmith-skills-prd.md` and
> `tasks/stories.json`. This file describes the *current* code; the PRD is authoritative
> for the remaining target design.

## Project Overview

ThreatSmith is an AI-powered threat modeling engine supporting multiple methodologies (PASTA, 4QF+STRIDE). Each methodology is packaged as a distributable **Agent Skill** that a coding agent (Claude Code, Codex) loads natively. The skills are the single source of truth for all prompt content. A methodology can be consumed two ways from that one source: directly inside a coding agent (a human picks a mode and walks the stages), or via the ThreatSmith CLI, which orchestrates the *installed* skills under the hood, driving the agent engine stage by stage and producing structured markdown deliverables.

## Technical Stack

- Python 3.12+, src layout with hatchling build backend
- Typer for CLI, stdlib logging for all output
- No runtime dependencies beyond typer — engines are invoked via subprocess
- Skills are plain markdown (`SKILL.md` + `references/`); no runtime code

## Development Commands

```bash
uv run pytest                # run all tests
uv run ruff check --fix      # lint (auto-fix; never manually fix lint issues)
uv run ruff format           # format (always use this, never manually reformat)
make build-skills            # rebuild built skills from skills-src/ into build/skills/
```

Always run `uv run ruff check --fix` and `uv run ruff format` to let the tools auto-fix issues. Do not run the check-only variants (`ruff check` without `--fix`, `ruff format --check`) and then manually apply fixes.

## Architecture

### Two halves: skills (content) + Python (orchestration)

**Skills** hold all prompt content and are authored, then built into self-contained form:

```
skills-src/                         # authored sources — SINGLE SOURCE OF TRUTH
  _shared/references/               # canonical shared reference markdown
    owasp-web/api/llm/mobile-top-10.md, scanners.md
  threatsmith-stride-4q/            # SKILL.md + references/stages/01..05-*.md
  threatsmith-pasta/                # SKILL.md + references/stages/01..08-*.md
  threatsmith-secure/               # consumption skill (plan / review modes)
build/skills/                       # built, self-contained, COMMITTED, CI drift-guarded
  <skill>/references/stages/ + synced owasp-*.md, scanners.md
```

Shared references live once in `skills-src/_shared/references/` and are synced into each skill's own `references/` at build time, so every built skill is self-contained while maintenance stays single-source. Stage prompts express reference conditions in natural language ("if the system exposes HTTP APIs, also consult owasp-api-top-10.md") — the agent decides what applies. There is no CLI-side conditional injection and no scanner detection; scanner usage is documented in `scanners.md` and the agent runs what's available.

**Python** is thin orchestration that drives the installed skills (Model B):

```
CLI (main.py)
  → pack = get_framework(name)          # default "stride-4q", via --framework or .threatsmith.yml
  → Orchestrator(engine, repo_path, pack, output_dir, mode, user_objectives).run()
      → for stage in pack.stages + [pack.report_stage]:
          compose_stage_instruction(stage, pack, mode, output_dir, user_objectives)
            → "Use skill `<skill>`. Run stage NN (Name) in <mode> mode. Output: <dir>/.
               Prior outputs are in <dir>/ — read from there. Non-interactive single stage."
          engine.execute(instruction, working_directory, output_dir) → exit_code
          validate stage.output_file exists → advance
  → generate_metadata(...) + write_metadata(...)   # provenance, written after the run
```

### Key interfaces

- **`frameworks.py`** (single module): defines `StageSpec` and `FrameworkPack` (frozen dataclasses — pure read-only metadata: stage order, expected output filenames, report stage, and `skill_name` pointing at the providing skill), the registry (`register_framework` / `get_framework` / `list_frameworks` over `_REGISTRY`), and the two built-in pack literals `STRIDE_4Q` and `PASTA`, which register themselves at import time. No prompt strings, no `build_prompt`, no `StageContext`.
- **`compose_stage_instruction()`** (in `orchestrator.py`): pure function that builds the per-stage *instruction* string (skill name, stage number/name, mode, output dir, prior-output location). It composes an instruction, not prompt text — the prompt content lives in the installed skill.
- **`Orchestrator`** (`orchestrator.py`): framework-agnostic dataclass. `run()` iterates `pack.stages + [pack.report_stage]`, calls `compose_stage_instruction`, invokes the engine once per stage (fresh session), validates the expected output file, and tracks `stages_completed`. Returns 0 on success, 1 on first failure. Prior-stage context is passed **by file pointer** — never inlined.
- **Engine** (`engines/base.py`): ABC with `execute(prompt, working_directory, output_dir) -> int`. Thin subprocess wrappers. `get_engine(name, verbose)` maps `"claude-code"` / `"codex"` to engine classes.
- **`_build_skills.py`** + `scripts/build_skills.py`: `build_skills(src_root, out_root)` wipes `out_root`, copies each authored skill, and syncs its declared shared references (`SKILL_SHARED_REFS`) into the skill's `references/`. Run via `make build-skills`.

### Import graph

```
frameworks.py        ← pure dataclasses + registry + built-in literals (no threatsmith imports)
engines/base.py      ← stdlib only
orchestrator.py      ← imports frameworks, engines.base; defines compose_stage_instruction
utils/metadata.py    ← imports threatsmith.__version__, frameworks
main.py              ← imports frameworks, orchestrator, engines, utils
_build_skills.py     ← stdlib only (shutil/pathlib)
```

## Package Structure

- **`__init__.py` files stay thin** — re-exports only, no implementation. Put logic in named modules and re-export via explicit `from module import X` + `__all__`.
- **Frameworks are data, orchestration is behavior.** Framework metadata lives in `frameworks.py`; the orchestration loop and instruction composition live in `orchestrator.py`. Don't merge the two — keep data separate from the code that runs it.

## Codebase Patterns

- **Skills are the source of truth.** Never put prompt content in Python. Edit prompts in `skills-src/`, then `make build-skills`. Never hand-edit `build/skills/` — it's regenerated and CI fails on drift.
- **Instruction, not prompt.** `compose_stage_instruction` names the skill + stage + mode + output dir and points at prior outputs by path. No prior-stage text, no XML `<prior_stages>` block, no reference strings are inlined.
- **`or None` guards**: `objectives.get("business_objectives") or None` treats both missing and empty-string values as absent.
- **Frozen packs**: `StageSpec` / `FrameworkPack` are `frozen=True`. The built-in `STRIDE_4Q` / `PASTA` singletons are safe to share; construct a fresh pack in tests when you need different field values.
- **Logging**: modules use `logger = logging.getLogger(__name__)`. CLI configures via `configure_logging(verbose)` in `utils/logging.py`. DEBUG = verbose, INFO = progress, WARNING/ERROR = failures.
- **metadata.json**: `generate_metadata(engine_name, framework, mode, stages_completed, user_objectives)` returns a `ThreatSmithMetadata` dataclass (records the generation `mode`; no scanner fields). Written *after* the run so `stages_completed` is accurate. `write_metadata(output_dir, metadata)` serializes to JSON. Provenance only — no consumer is required to read it.
- **CLI structure**: `app` is a Typer app with a root callback (`_root`) carrying the eager `--list-frameworks` flag, a `model` command (the run; `path` is a required argument), and a `skills` sub-Typer with `install` (copies bundled skills into the engine's `skills_dir`) and `list` (shows each bundled skill and whether it is installed for the engine). Add new top-level verbs as `@app.command()`; group skill-management verbs under `skills_app`. The console-script entry point is the `app` object (`threatsmith.main:app`), so renaming command functions is safe.
- **Engine install target**: each `Engine` exposes a `skills_dir` property (abstract on the base) — `~/.claude/skills` for claude-code, `~/.codex/skills` for codex. `skills install` resolves the engine, reads `skills_dir`, and calls `install_skills()`. This is how "the install target accounts for the selected engine."
- **`--engine` is required on all commands (no default)** — `model`, `skills install`, `skills list`. For the skills commands the engine selects a filesystem destination, so a default would silently target the wrong agent; `model` requires it too for consistency. Required options use the Annotated form with no `= default` and `show_default=False` (the latter suppresses Typer's cosmetic `[default: None]` line). Don't reintroduce a default without revisiting the footgun.
- **`no_args_is_help=True`** is set on `model`, `skills install`, `skills list`, and the `skills` group, so a bare invocation prints help (with the required `--engine`) instead of a terse missing-option error. A *partial* invocation (some args, still missing `--engine`) keeps the specific error — the intended CLI-UX behavior (don't dump full help on every error; do show help when there's nothing actionable). **Requires `typer>=0.19.2`**: in 0.16 `no_args_is_help` on a command with a required option renders help followed by an empty error panel (and a spurious `(env var: 'None')` in the partial-input error). The dependency pin in `pyproject.toml` documents this.
- **Skill install/list**: `_install_skills.py` holds both. `install_skills(skills_dir, source=None)` copies each bundled skill dir into `skills_dir/<name>`, removing an existing install of that skill first (clean refresh) but never wiping the whole `skills_dir` (other skills survive); returns `list[InstalledSkill]`. `list_skill_statuses(skills_dir, source=None)` returns `list[SkillStatus]` (name, installed, destination) — a skill is "installed" when `skills_dir/<name>` is a directory; this is the same check US-012 pre-run validation should use. Both default `source` to `get_bundled_skills_path()`; tests pass a fake source tree.
- **CLI config**: `_load_config(path)` reads `.threatsmith.yml` from the target repo (trivial line-by-line parser, no PyYAML). `--framework` defaults to the config value or `"stride-4q"`. `--list-frameworks` prints registered packs and exits.

## Testing Patterns

- Tests live in `tests/` at root level. Current files: `test_frameworks.py`, `test_stride_4q_pack.py`, `test_orchestrator.py` (which also holds the `compose_stage_instruction` tests), `test_engines.py`, `test_cli.py`, `test_metadata.py`, `test_build_skills.py`, `test_package_data.py`, `test_install_skills.py`, and the E2E pair `test_e2e_pasta.py` / `test_e2e_stride_4q.py`.
- **CLI invocation in tests**: the run command is a subcommand — invoke it as `runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code", ...])`, and skills commands as `["skills", "install", "--engine", ...]` / `["skills", "list", "--engine", ...]`. `--engine` is required, so omitting it errors (exit 2) — happy-path tests must pass it. Only `--list-frameworks` is a bare top-level flag (`runner.invoke(app, ["--list-frameworks"])`). Because of `no_args_is_help`, a *bare* subcommand invocation returns help (exit 2), not a missing-arg error; to assert the required-engine error, pass another arg (e.g. `["skills", "install", "--verbose"]`) or, for `model`, a path with no `--engine`.
- Do not write tests for string constants — test logic and behavior only.
- Use `@pytest.mark.parametrize` for tests that share structure with different inputs (e.g. the instruction-composition assertions).
- Split a test file proactively as it approaches ~800 lines.
- **Mock engine in E2E/orchestrator tests**: closure over `output_dir` in `execute_side_effect(instruction, working_directory, output_dir)` writes stage files; track call count via `engine.execute.call_count` or a `{"n": 0}` dict.
- **Registry isolation**: `test_frameworks.py` uses an autouse `clean_registry` fixture that snapshots and restores `_REGISTRY` around each test.
- **Patch location for CLI tests**: patch `threatsmith.main.get_engine` and `threatsmith.main.get_framework` (the CLI imports them into its own namespace).
- `generate_metadata()` is safe to use unpatched in tests — it falls back to `"unknown"` for git failures.
- Test logging with `caplog.at_level(logging.DEBUG, logger="threatsmith.module_name")`.
