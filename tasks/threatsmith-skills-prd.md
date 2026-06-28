# ThreatSmith v0.4.0 — Threat Modeling as Agent Skills — Product Requirements Document

**Author:** Abed
**Date:** June 2026
**Status:** Draft
**Builds on:** ThreatSmith v0.3.1 (pluggable framework packs — 4QF+STRIDE and PASTA — with prompt content stored as Python string constants, assembled by the orchestrator and run as fresh per-stage engine subprocesses)

---

## 1. Overview

### 1.1 Release Goal

This release repackages ThreatSmith's threat modeling methodologies as **distributable Agent Skills** — the SKILL.md-style format that coding agents (Claude Code, Codex) load natively — and reworks the prompts so each skill serves multiple use cases and audiences rather than only the CLI's "point at an existing repo" flow.

After this release a methodology can be consumed two ways from one source of truth:

1. **Directly inside a coding agent** — a person installs the skill and runs a threat model themselves, picking a mode (from existing code, from design docs, or interactive pair modeling).
2. **Via the ThreatSmith CLI** — the CLI orchestrates the *installed* skills under the hood, driving the agent engine stage by stage exactly as today.

The release also delivers the consumption half of the thesis behind threat models: a **secure-coding skill** that feeds an existing threat model into a coding agent at two moments — when planning a change and when reviewing code — so the agent keeps threats and mitigations in context and produces more secure output.

### 1.2 Scope

**In scope:**

- Convert the two existing framework packs (`stride-4q`, `pasta`) into self-contained Agent Skills, one skill per framework.
- Make the skills the **single source of truth** for prompt content; remove prompt strings from Python.
- Rework each framework skill's stage prompts to support three **modes**: from-code, from-docs, and pair.
- Make skills **stage-addressable**: each skill supports single-stage, non-interactive invocation (used by the CLI) in addition to a human "walk all stages" entry point.
- Refactor the orchestrator/assembler so the CLI drives the *installed* skill by name + stage (Model B), passing prior-stage context by **file pointer** rather than inlined text.
- A **secure-coding consumption skill** with `plan` and `review` modes that is threat-model-source-agnostic.
- **Shared reference handling**: canonical reference markdown synced into each self-contained skill; retire CLI-side conditional-injection logic in favor of agent-decided, in-prompt reference selection.
- **Build + distribution**: a build step syncs shared references into each skill and writes self-contained, committed built skills (CI-verified for drift); these are bundled in the package; a `threatsmith install-skills` command installs them into the agent's skills directory; the CLI validates skill presence before running.
- CLI `--mode` flag (from-code default, from-docs); `install-skills` command; validate-or-exit behavior.
- `metadata.json` gains a `mode` field; otherwise retained as a generation-side provenance artifact.

**Out of scope (deferred):**

- LINDDUN Pro and MAESTRO skills — they remain deferred as in v0.3.0. The skill architecture must not preclude them.
- A dedicated Claude Code **subagent** wrapping `review` mode (fast-follow; the portable consumption skill ships first).
- Pair mode via the CLI — pair is interactive and skill-only this release.
- Deterministic, guaranteed reference coverage (we move to agent-decided references; deterministic injection can return later if quality warrants).
- Incremental updates / threat-model diff / auto-PR — unchanged roadmap items.
- Standalone (non-package) skill distribution / marketplace publishing.
- Within-stage parallel fan-out (sub-agents across system partitions inside a heavy stage). Stages stay sequential this release; fan-out is a future skill-prompt optimization that needs no orchestrator change (see §7).

### 1.3 Design Principles

Carried forward:

- **Leverage, don't rebuild.** The wrapper orchestrates; agents do the analysis.
- **Stage isolation with accumulated context.** Fresh, focused execution per stage; prior outputs as lean context.
- **Deliverables over conversation.** Validate that files exist; don't parse agent dialogue.
- **Extensibility by design.** New engines, scanners, stages, and frameworks without structural changes.
- **Methodology as configuration, not code.** Adding a framework means authoring a skill + registering thin metadata.

New in this release:

- **Skills are the unit of distribution and the source of truth.** *(New)* Prompt content lives in skills, not Python. There is exactly one place to maintain a methodology's prompts.
- **One methodology, multiple modes.** *(New)* The same skill serves from-code, from-docs, and pair modeling, and is usable by both security experts and non-experts.
- **Consume via content, not format.** *(New)* Anything that reads a threat model binds to readable markdown in a directory — never to framework-specific filenames or `metadata.json`.
- **Accessible to non-experts.** *(New)* Prompts guide software engineers and vibe coders, not only AppSec specialists.

---

## 2. Architecture

### 2.1 Skills as the source of truth

A framework becomes a self-contained skill directory following **Agent Skill conventions**: a top-level `SKILL.md` (orchestration + mode handling for humans) plus a `references/` directory holding everything loaded on demand. Per skill conventions the only bundled-resource directories are `scripts/`, `references/`, and `assets/` — there is no separate top-level `stages/` directory. The per-stage prompt files are "docs loaded as needed," so they live **under `references/`** (e.g. `references/stages/NN-*.md`), alongside the methodology's reference material (OWASP, STRIDE, scanner guidance) which is synced in from a canonical source at build time.

Skills are kept in two forms: **authored sources** (the single source of truth — `SKILL.md` + `references/stages/*.md` + any skill-specific references, *without* the shared reference content) and **built skills** (fully self-contained, shared references synced in, committed to the repo and rebuilt by CI). See §2.7.

Illustrative layout (directory/role level — exact names are the implementor's choice):

```
# Authored sources (single source of truth) ──────────────────────────
skills-src/
  _shared/references/                # canonical shared reference content
    stride-categories.md
    owasp-web-top-10.md
    owasp-api-top-10.md
    owasp-llm-top-10.md
    owasp-mobile-top-10.md
    scanners.md                      # how to run Semgrep / Trivy / Gitleaks
  threatsmith-stride-4q/
    SKILL.md                         # mode selection + stage walkthrough (human entry)
    references/
      stages/
        01-system-model.md
        02-threat-identification.md
        03-mitigations.md
        04-validation.md
        05-report.md
  threatsmith-pasta/
    SKILL.md
    references/stages/  (01-objectives … 08-report)
  threatsmith-secure/                # consumption skill (plan / review)
    SKILL.md

# Built, self-contained skills (committed; CI-verified) ───────────────
build/skills/
  threatsmith-stride-4q/
    SKILL.md
    references/
      stages/  (01 … 05)
      stride-categories.md           # synced from _shared
      owasp-web-top-10.md            # synced
      owasp-api-top-10.md            # synced
      owasp-llm-top-10.md            # synced
      scanners.md                    # synced
  threatsmith-pasta/   (+ synced owasp-*.md, scanners.md)
  threatsmith-secure/
    SKILL.md
```

Each stage file (`references/stages/NN-*.md`) is authored to:

- State the stage's objective, required output file, and output structure.
- **Point to prior stage outputs by path** (read `threatmodel/0X-*.md` as needed) rather than expecting inlined text.
- Include **mode framing** (from-code / from-docs / pair) so the same stage adapts to whether code exists, only docs exist, or a human is collaborating.
- Give **conditional reference guidance** ("if the system exposes HTTP APIs, also consult `references/owasp-api-top-10.md`"), letting the agent decide based on the system model it built.

### 2.2 Execution model — three surfaces, one stage content

Per-stage isolation is preserved. The same `stages/*.md` content is reached through three surfaces:

```
                         ┌──────────────────────────────┐
                         │   stages/NN-*.md (content)    │
                         └───────────────┬──────────────┘
            ┌──────────────────┬─────────┴────────┬───────────────────┐
            ▼                  ▼                    ▼
   CLI orchestration   Direct human use        Pair mode
   (Model B)           (from-code/from-docs)   (interactive, skill-only)
   per-stage engine    one session, agent      one session, agent asks
   subprocess, drives  walks stages, re-reads  questions, writes each
   installed skill by  prior output files      stage doc, confirms,
   name + stage + mode between stages          advances
```

**CLI orchestration (Model B).** The orchestrator loops the framework's stages and, for each, invokes the engine once (fresh session) instructing it to **use the installed skill by name and execute a single stage** in the selected mode, pointing it at `threatmodel/` for prior outputs. The orchestrator validates the expected output file, then advances. This requires the skills to be installed and the engine to load a named skill non-interactively — supported by both Claude Code and Codex, interactively and non-interactively.

**Direct human use.** A person invokes the skill in their coding agent. `SKILL.md` prompts for a mode (unless one was supplied), then walks the stages within one session, writing each output file and re-reading only the prior files the next stage needs — keeping working context lean.

**Pair mode.** Skill-only and interactive. The agent advances stage by stage, asking the human clarifying questions, writing each stage doc, confirming, and proceeding. Best for greenfield work where docs and decisions are still forming.

### 2.3 Modes

| Mode | Source material | Surfaces | Audience |
|------|-----------------|----------|----------|
| `from-code` | Existing repository (+ docs if present) | CLI + direct | Engineers, AppSec |
| `from-docs` | Design docs only (PRD/plan/spec), code not implemented | CLI + direct | Engineers planning, AppSec |
| `pair` | Whatever exists; gaps filled by Q&A | Direct only (interactive) | AppSec experts, also non-experts |

Mode is chosen by prompt at invocation, or supplied up front (CLI `--mode`, or an argument to the skill). Each stage prompt carries mode-specific framing so behavior adapts without separate stage files.

**from-docs context discovery.** A from-docs run is invoked from a root directory; the agent **discovers available context itself** — README, design docs, specs, PRDs, plan files — rather than relying on any hardcoded paths. The invoker may also supply alternative or additional context for the agent to pull in: ticket IDs, Confluence page links, Linear issues, or other external sources. When such sources are referenced and the corresponding MCP servers are available, the agent fetches that context directly. For example, a user might invoke from-docs with *"model the auth redesign described in LINEAR-482 and the Confluence page linked there, using the linear and confluence MCP servers"* — the skill instructs the agent to gather that context before producing the system model. Because the right context sources vary by use case, the skill defines the *behavior* (discover what exists locally; fetch what the invoker points to) rather than a fixed input contract or hardcoded paths.

### 2.4 Shared references — canonical + sync

Reference **content** lives once, canonically, as markdown. A sync step (run at packaging and as part of `install-skills`) copies each skill's required reference files into that skill's own `references/` directory, so every installed/distributed skill is self-contained while maintenance stays single-source. Updating OWASP is a single canonical edit + re-sync.

Reference **logic** is retired. The keyword-matching conditional-injection (`conditions.py`, `api_detected`/`llm_detected`) is removed. Stage prompts express conditions in natural language and the agent — which has just produced the system model — decides which reference files to consult.

**Scanners move entirely to the agent.** A shared reference file documents how to run common tools (Semgrep, Trivy, Gitleaks); the agent detects what is available and runs it. The CLI performs **no scanner detection** — coding agents are fully capable of this, and ThreatSmith should not duplicate their capabilities. There is no `scanner_stages` injection mechanism; the relevant stage prompt simply instructs the agent to use available scanners per the shared reference file.

### 2.5 Framework packs shrink to orchestration metadata

The Python framework packs do not disappear; they lose their embedded prompt strings and become **thin orchestration metadata** the CLI needs to drive a run: ordered stage list, expected output filenames, which skill provides the content, and the report stage. The `build_prompt` Python functions and `STAGE_PROMPT` constants are removed — the assembler no longer assembles prompt text; it composes a per-stage *instruction* that names the skill, stage, mode, and output, and points at prior outputs.

### 2.6 metadata.json

Retained as a **generation-side provenance artifact** only. It records engine, framework, mode, commit hash, branch, timestamp, user objectives, and stages completed. Scanner-availability fields are dropped, since the CLI no longer performs scanner detection. It anchors future incremental updates (commit hash) and re-run safety (framework-mismatch warning). **No consumer is required to read it.** The consumption skill may opportunistically use a present `metadata.json` (e.g., a staleness hint from the commit hash) but must degrade fully without it.

### 2.7 Built skills as committed artifacts

Skills are authored in *source* form and assembled into *built* form by a build step that syncs the required shared references into each skill's `references/` directory. The built, fully self-contained skills are **committed to the repo** (e.g. under `build/skills/`) for two reasons:

- **Clone-and-copy path.** A user can clone the repo and copy a ready-to-use skill directly into their agent's skills directory without running any build.
- **Single packaging/install source.** The packaged distribution and `threatsmith install-skills` both source from the built skills, so there is one canonical set of installable artifacts.

The build runs in **CI**, which **fails if the committed built skills differ from a fresh build** — a drift guard ensuring the committed artifacts can never silently fall out of sync with the authored sources or canonical references. Updating a methodology or a reference is therefore a single source edit plus a rebuild; the committed `build/` is regenerated, never hand-edited.

---

## 3. Functional Requirements

### 3.1 Framework skills (stride-4q, pasta)

Each shipped framework skill must:

- Provide a `SKILL.md` that, when invoked directly, prompts the user to choose a mode (or accepts a supplied mode) and then guides the agent through all stages to completion, writing each deliverable to the output directory.
- Provide one `stages/*.md` file per analysis stage plus the report stage, preserving the existing stage set and output filenames (stride-4q: 5 files; pasta: 8 files).
- Author each stage to support all three modes, to point to prior outputs by path, and to include agent-decided conditional reference guidance.
- Bundle (via sync) only the reference files it actually uses.
- Preserve the existing methodology content and quality — this is a rework of *delivery and modes*, not a redefinition of the methodologies.

### 3.2 Single-stage non-interactive invocation

Each framework skill must support being invoked to execute **exactly one stage** non-interactively, given: the stage to run, the mode, the output directory, and the location of prior outputs. This is the entry point the CLI uses under Model B. The behavior must match a human walking to that same stage.

### 3.3 Secure-coding consumption skill (`plan` / `review`)

A single consumption skill with two modes, threat-model-source-agnostic and composable:

- **`plan` mode.** Given a change description (and an in-progress plan/PRD/spec if present), it reads the threat model directory, extracts the threats, mitigations, trust boundaries, and required controls relevant to the change, and emits a **security augmentation layer** — threat-informed requirements/constraints/checklist — that the user or another planning skill folds into their artifact. It must **not** own or overwrite the planning document, so it composes with external planning skills in the same session.
- **`review` mode.** Given a diff/PR/working changes, it reads the threat model directory and reports whether the change introduces uncatalogued threats, fails to apply required mitigations, or weakens an existing control. Optional graceful staleness note if `metadata.json` is present.
- **Source-agnostic contract.** The skill binds only to "readable threat-model markdown in a directory it is pointed at." It must not require ThreatSmith-specific filenames or `metadata.json`, and must work on hand-authored threat models.

### 3.4 Skill build and reference sync

- Canonical reference markdown is the single source of truth.
- A build step assembles each skill in self-contained form by syncing its required references into its `references/` directory, and writes the result to a committed build location.
- The committed built skills let users clone-and-copy a skill without running a build.
- CI runs the build and fails if the committed built skills differ from a fresh build (drift guard).
- Adding/updating a reference is a single canonical edit followed by a rebuild; no skill prompt edits required, and the committed `build/` is regenerated rather than hand-edited.

### 3.5 Skill installation and CLI validation

- `threatsmith install-skills` installs the built (self-contained) skills into the agent's skills directory. It supports overwriting/refreshing existing installs.
- The built skills are **bundled in the package** so the CLI distribution is self-contained; `install-skills` copies them from the package into the engine's skills location.
- Before any run, the CLI **validates** that the required skill for the selected framework is installed. If missing, it exits with a clear message instructing the user to run `threatsmith install-skills`.

---

## 4. Design / Refactor Impact

- **Orchestrator.** Continues to iterate `pack.stages + [pack.report_stage]` and validate output files, but each iteration drives the engine to run the named installed skill for that stage in the selected mode, pointing at `threatmodel/` for prior outputs. It stops inlining accumulated prior-stage text.
- **Assembler.** No longer assembles prompt *text*. It composes a per-stage *instruction* (skill name, stage, mode, output dir, prior-output location). Reference resolution and conditional injection move into the skill prompts (agent-decided); the assembler's reference/condition responsibilities are removed.
- **Framework packs.** Lose `STAGE_PROMPT` constants and `build_prompt` functions; retain stage metadata and a pointer to the providing skill. The `prompts`/stage Python modules holding prompt strings are removed.
- **References.** `frameworks/references/*` prompt-string constants migrate to canonical markdown; `conditions.py` is deleted; `scanner_snippets.py` content moves to a shared reference markdown file.
- **Scanner detection.** The CLI's `detect_scanners()` is removed; scanner availability is no longer detected or recorded. Scanner usage guidance lives in the shared reference file and is exercised by the agent.
- **Build pipeline.** A new build step syncs canonical references into each skill and emits self-contained skills to a committed location; CI verifies the committed build matches a fresh build, and packaging sources from it.
- **metadata.** `generate_metadata` gains `mode`; `metadata.json` otherwise stable. No consumer dependency introduced.
- **CLI.** Adds `install-skills`, `--mode`, and pre-run skill validation. `--rerun-stage` continues to validate against the selected framework's stage count.

---

## 5. CLI Changes

| Command / Flag | Type | Default | Description |
|----------------|------|---------|-------------|
| `threatsmith install-skills` | command | — | Install/refresh bundled skills (with synced references) into the agent's skills directory |
| `--mode` | string | `from-code` | Generation mode for CLI runs: `from-code` or `from-docs`. (`pair` is skill-only and not a CLI mode.) |
| `--engine` | string | `claude-code` | Unchanged; also determines the install target for `install-skills` |
| (pre-run validation) | behavior | — | If the required skill is not installed, exit with guidance to run `threatsmith install-skills` |

`metadata.json` adds a `mode` field recording which generation mode produced the model.

Backward compatibility: the default framework (`stride-4q`) and default behavior (analyze existing code) are unchanged in intent, but a first run after upgrade now requires `threatsmith install-skills`. This is a deliberate, documented change driven by the Model B decision.

---

## 6. Open Questions

| Question | Context |
|----------|---------|
| Reference coverage without deterministic injection | Moving to agent-decided references trades guaranteed coverage for leaner, context-aware selection. Monitor output quality; deterministic injection can return as an opt-in if coverage regresses. |
| Pair-mode deliverable consistency | Pair mode is interactive and free-flowing; we must ensure it still produces the same numbered deliverables as the other modes so downstream consumption is uniform. |

---

## 7. Key Decisions and Rejected Alternatives

These record the reasoning behind non-obvious choices so they are not quietly re-litigated by a future implementor who lacks the original discussion.

| Decision | Chosen | Rejected alternative(s) | Why |
|----------|--------|-------------------------|-----|
| How the CLI consumes skills | **Model B** — the CLI drives the *installed* skill by name + stage; the engine loads it. | **Model A** — the CLI reads bundled stage content from package data and inlines it into the prompt; the engine never loads a named skill. | Model B gives a single, dogfooded execution path: the CLI exercises the exact skill a human would, so behavior can't diverge between surfaces. Accepted cost: the CLI depends on skills being installed (hence `install-skills` + validate-or-exit) and couples to each engine's skill-loading. **Fallback:** if an engine cannot load a named skill non-interactively, inline that engine's stage content (Model A) for that engine only while keeping Model B elsewhere. |
| Skill packaging granularity | **One skill per framework** (`threatsmith-stride-4q`, `threatsmith-pasta`). | A single umbrella `threat-model` skill (framework + mode as args); or a framework×mode matrix of skills. | "Frameworks become skills" is the cleanest mental model. An umbrella skill becomes a branching mess as frameworks grow; the matrix is overkill because modes are behavioral variations of one methodology, not separate methodologies. |
| Shared reference content | **Canonical markdown + sync into each self-contained skill** (Option C), with committed built artifacts. | Duplicate references by hand per skill (Option A); or a shared references bundle skills point at (Option B). | C preserves single-point maintenance *and* keeps each installed/distributed skill self-contained (which Model B and Claude Code's skill model both want). A drifts; B breaks skill self-containment with fragile cross-directory paths. |
| Stage prompt location | **Under `references/` (e.g. `references/stages/NN-*.md`).** | A top-level `stages/` directory in each skill. | Agent Skill conventions define only `scripts/`, `references/`, and `assets/` as bundled-resource dirs. Stage prompts are "docs loaded as needed" → `references/`. Confirmed against the skill-creator guidance. |
| Prior-stage context passing | **Point to files** — the agent reads prior outputs from the output directory. | Keep injecting full prior-stage text as XML; keep CLI-side keyword conditions. | Every execution surface has filesystem access to the output dir. Pointing keeps context lean on large repos and simplifies the assembler. |
| Conditional references | **Agent-decided in-prompt** (retire `conditions.py`). | Deterministic CLI-side keyword matching (`api_detected`/`llm_detected`). | The agent has just built the system model and can decide which references apply. Trades guaranteed coverage for leaner, context-aware selection; deterministic injection can return as an opt-in if coverage regresses (see Open Questions). |
| Scanner handling | **Delegated entirely to the agent** via a shared reference file; CLI `detect_scanners()` removed. | CLI detects scanners and injects/declares availability per stage. | Coding agents can detect and run tools themselves; ThreatSmith should not duplicate that capability. |
| Built skills in the repo | **Committed `build/` artifacts, CI drift-guarded.** | Build only at packaging/CI time; don't commit built skills. | Committing lets users clone-and-copy a ready skill with no build step, and gives packaging/`install-skills` one canonical source. CI rebuilds and fails on diff so the committed artifacts can't silently rot. |
| Consumption deliverable | **One `threatsmith-secure` skill with `plan` + `review` modes**, source-agnostic. | A Claude Code subagent now; two separate skills; binding to a `metadata.json` manifest. | One skill mirrors the generation packaging and is portable across engines. Binding to readable threat-model markdown (not filenames or `metadata.json`) keeps it usable on hand-authored models and future tools. Subagent wrapper deferred to a fast-follow. |
| metadata.json | **Kept as generation-side provenance only.** | Drop it; or make it the consumption contract. | It anchors provenance, future incremental updates (commit hash), and re-run safety — none of which need a consumer. Consumers must not depend on it, to stay source-agnostic. |
| Stage execution ordering | **Sequential — one stage at a time, each consuming the prior stage's deliverable as input.** | Run stages concurrently, one sub-agent per stage. | The methodologies impose a hard data dependency, not an arbitrary order: threats (02) are defined against the system model (01); mitigations (03) require the threats; validation (04) requires the mitigations; the report consolidates last. 4QF and PASTA are by definition pipelines. Concurrent stages would analyze inputs that don't yet exist. Each stage is *already* a fresh per-stage agent (Model B); the ordering is the load-bearing constraint and cannot be removed. **Note:** parallelism *is* available on a different axis — *within* a heavy stage (e.g. threat or vulnerability analysis), the agent can fan out sub-agents across system partitions (components / trust boundaries / data flows) and merge. That is an internal execution detail of a single stage, lives in the skill prompt, and does **not** touch the orchestrator or the per-stage contract — so it is deferred as a future skill-level optimization, not a v0.4.0 change. The merge step must explicitly own cross-partition threats (those on the flows *between* components), which naive partitioning drops. |
