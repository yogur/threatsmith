# ThreatSmith v0.2.0 — Product Requirements Document

**Author:** Abed
**Date:** March 2026
**Status:** Draft — MVP Scope

---

## 1. Overview

ThreatSmith v0.2.0 is a rewrite of ThreatSmith, an AI-powered PASTA (Process for Attack Simulation and Threat Analysis) threat modeling engine. The original implementation used LangGraph to orchestrate custom agents with hand-built code exploration tools and context management. Version 0.2.0 replaces that engine with a thin Python wrapper around AI coding agents — specifically Claude Code and OpenAI Codex — that already possess native code navigation, file manipulation, and shell execution capabilities.

This architectural shift eliminates the most complex and fragile parts of the original system (custom tooling, context plumbing, agent orchestration) and lets development focus on what matters: high-quality threat modeling deliverables and workflow automation.

### 1.1 Problem Statement

PASTA threat modeling is rigorous but time-consuming. It involves seven structured stages, each requiring specific documentation artifacts (data flow diagrams, threat inventories, attack trees, etc.). Application security teams rarely adopt it fully because the manual effort is prohibitive. ThreatSmith v0.1.0 demonstrated that AI agents can automate PASTA effectively, but the LangGraph-based implementation suffered from:

- Complex custom tool plumbing for code exploration
- Fragile context management across agent stages
- Mixed results from prompt engineering due to tool limitations
- High maintenance burden for scanner integrations and diagram validation
- Limited accessibility (required Python environment setup and API keys)

### 1.2 Solution

ThreatSmith v0.2.0 wraps AI coding agents (Claude Code, Codex) that already solve the hardest problems — code navigation, file reading, command execution, and long-context reasoning — and focuses the wrapper on orchestration, deliverable management, and workflow automation. Anyone with a Claude Code or Codex subscription can run it.

### 1.3 Key Design Principles

- **Leverage, don't rebuild.** AI coding agents already have code exploration, file I/O, and shell access. The wrapper orchestrates; it does not replicate.
- **Stage isolation with accumulated context.** Each PASTA stage runs in a fresh agent session but receives all prior stage outputs. This mirrors how a human analyst works: read the prior deliverables, then produce the next one.
- **Deliverables over conversation.** Every stage produces a concrete markdown artifact. The wrapper validates that expected outputs exist; it does not parse agent dialogue.
- **Extensibility by design.** The engine abstraction, scanner detection, and stage architecture are built to support new engines, tools, and stages without structural changes.

---

## 2. Architecture

### 2.1 High-Level Flow

```
┌──────────────┐     ┌─────────────────────┐     ┌──────────────────┐
│  CLI / User  │────▶│  Python Wrapper      │────▶│  AI Coding Agent │
│  Input       │     │  (Orchestrator)      │     │  (Claude Code /  │
│              │     │                      │     │   Codex / ...)   │
│  --engine    │     │  • Stage sequencing  │     │                  │
│  --repos     │     │  • Context assembly  │     │  • Code nav      │
│  --parallel  │     │  • Scanner detection │     │  • File I/O      │
│              │     │  • Output validation │     │  • Shell exec    │
└──────────────┘     │  • Batch/PR mgmt    │     │  • Reasoning     │
                     └─────────────────────┘     └──────────────────┘
```

### 2.2 Engine Abstraction

The wrapper defines a minimal engine interface that all supported coding agents must satisfy:

```
Engine Interface:
  - execute(prompt, working_directory) → exit_code
  - Working directory: the target repo root
  - Output contract: the agent writes expected files to threatmodel/ within the working directory
  - The wrapper does NOT parse agent conversational output — it validates that expected deliverable files were produced
```

Engine selection via `--engine` CLI parameter (e.g., `--engine claude-code`, `--engine codex`). Each engine adapter translates the interface into the appropriate CLI invocation:

- **Claude Code:** `claude -p <prompt>` (prompt mode, non-interactive; working directory set via subprocess)
- **Codex:** Equivalent CLI invocation per Codex's interface
- **Future engines:** Implement the same interface

### 2.3 Stage Execution Model

The pipeline consists of 7 PASTA analysis stages plus a report consolidation step. Each stage executes as follows:

1. **Wrapper assembles the prompt** — system prompt (stage-specific instructions) + user prompt (prior stage outputs injected as structured context, scanner availability info, OWASP references where applicable, commit hash, user-supplied objectives)
2. **Wrapper invokes the engine** — fresh agent session with the assembled prompt and the repo as working directory
3. **Agent performs analysis** — reads code, runs tools if instructed, writes its deliverable to `threatmodel/`
4. **Wrapper validates output** — checks that the expected output file was created
5. **Wrapper proceeds to next stage** — the new deliverable joins the accumulated context for subsequent stages

Context accumulation: Stage N receives the outputs of stages 1 through N-1. This mirrors how a security engineer works through PASTA — each stage builds on the structured findings of all prior stages. Counter-intuitively, this can improve agent performance because the accumulated context tells the agent where to look and what to look for, reducing blind codebase exploration.

### 2.4 Output Structure

All deliverables are written to a `threatmodel/` directory at the repository root:

```
threatmodel/
  metadata.json                    # Run metadata (see below)
  01-objectives.md                 # Stage 1: Business objectives & data sensitivity
  02-technical-scope.md            # Stage 2: Technology stack & dependencies
  03-application-decomposition.md  # Stage 3: Architecture, DFDs, trust boundaries
  04-threat-analysis.md            # Stage 4: Threat identification & attack scenarios
  05-vulnerability-analysis.md     # Stage 5: Vulnerability findings & CVSS scoring
  06-attack-modeling.md            # Stage 6: Attack trees & exploitation paths
  07-risk-and-impact-analysis.md   # Stage 7: Risk qualification, countermeasures, residual risk
  08-report.md                     # Consolidated executive report (non-PASTA step)
```

**Numbered prefixes** make ordering unambiguous for both humans and AI agents consuming the artifacts.

**Individual stage files are preserved** alongside the consolidated report. This is important for:

- **Incremental updates (phase 2):** re-run only the stages affected by code changes
- **Selective consumption by AI agents:** a developer fixing an auth issue needs stages 4–5, not the full objectives analysis
- **Debuggability:** if a stage produces weak output, re-run just that stage
- **Granular review:** security reviewers can drill into specific stages

**metadata.json** captures run context:

```json
{
  "threatsmith_version": "0.2.0",
  "engine": "claude-code",
  "commit_hash": "a1b2c3d",
  "branch": "main",
  "timestamp": "2026-03-12T14:30:00Z",
  "scanners_available": ["semgrep", "trivy"],
  "scanners_unavailable": ["gitleaks"],
  "user_objectives": {
    "business": "Protect user data, meet GDPR",
    "security": "Reduce data exfiltration risk"
  }
}
```

The commit hash and metadata lay the foundation for the incremental update feature in phase 2 without adding MVP complexity.

---

## 3. PASTA Stages

The pipeline implements all seven PASTA stages faithfully, plus a report consolidation step. Each stage maps to a dedicated prompt template. The wrapper injects dynamic context (prior outputs, scanner info, OWASP references, commit hash) into the template before passing it to the engine.

### Stage 1 — Define Objectives

**Input:** Repo access, optional user-supplied business/security objectives
**Output:** `01-objectives.md`
**Focus:** Business objectives and application purpose. Security, compliance, and legal requirements (GDPR, HIPAA, PCI-DSS, licensing). Business impact analysis including impact to mission, recovery processes, and budget. Operational impact on existing processes and personnel. Examines README, docs, config files, data models, and package metadata.

### Stage 2 — Define Technical Scope

**Input:** Repo access + Stage 1 output
**Output:** `02-technical-scope.md`
**Focus:** Boundaries of the technical environment including data classification. Infrastructure, application, and software dependencies with level of impact documented. Supply chain landscape and dependency relationships. Deployment patterns, containerization, cloud configurations, and CI/CD.

### Stage 3 — Application Decomposition

**Input:** Repo access + Stages 1–2 outputs
**Output:** `03-application-decomposition.md`
**Focus:** Use case identification, application entry points, and trust levels. Actors, assets, services, roles, and data sources. Data flow diagramming (Mermaid) showing data in motion and at rest with trust boundaries (existing and proposed). Complete documentation of all data touched and its classification.

### Stage 4 — Threat Analysis

**Input:** Repo access + Stages 1–3 outputs + OWASP reference context (see Section 4)
**Output:** `04-threat-analysis.md`
**Focus:** Probabilistic attack scenario analysis covering any scenario that could occur. Regression analysis on security events touching similar components. Threat intelligence correlation from available sources. Systematic STRIDE analysis across all major components identified in Stage 3. OWASP Top 10 cross-referencing for coverage validation. Must cover all components — partial analysis is unacceptable.

### Stage 5 — Vulnerability and Weakness Analysis

**Input:** Repo access + Stages 1–4 outputs + scanner availability context (see Section 5)
**Output:** `05-vulnerability-analysis.md`
**Focus:** Examination of existing vulnerability data and scanner results. Threat-to-vulnerability mapping using threat trees. Design flaw analysis through use and abuse cases. CVSS 3.1 scoring and CWE/CVE enumeration. Assessment of impacted systems, sub-systems, and data — whether the current state is vulnerable and how changes affect that assessment. Actionable remediation guidance with priority ranking.

### Stage 6 — Attack Modeling

**Input:** Repo access + Stages 1–5 outputs
**Output:** `06-attack-modeling.md`
**Focus:** Attack surface analysis for impacted components. Attack tree development using Mermaid diagrams, leveraging MITRE ATT&CK where applicable. Attack-to-vulnerability-to-exploit analysis using attack trees. Summary of impact with explanation of each risk. Must cover all significant threats from Stage 4.

### Stage 7 — Risk and Impact Analysis

**Input:** Repo access + Stages 1–6 outputs
**Output:** `07-risk-and-impact-analysis.md`
**Focus:** Qualification and quantification of business impact. Countermeasure identification and residual impact assessment. Risk mitigation strategies with analysis of mitigation effectiveness versus cost to implement. Identification of residual benefits (e.g., a mitigation applied to one component improving security for other systems that access it). Development of prioritized remediation roadmap based on residual risk.

### Report Consolidation (Post-Pipeline Step)

**Input:** Stages 1–7 outputs (repo access not strictly required)
**Output:** `08-report.md`
**Focus:** Executive summary of critical findings. Consolidation of all stage outputs into a single cohesive document. Filters conversational artifacts, preserves all technical content, Mermaid diagrams, scores, and recommendations. No new analysis — pure consolidation and professional formatting. This is not a PASTA stage; it is a deliverable generation step that packages the analytical outputs for consumption.

---

## 4. OWASP Reference Integration

### 4.1 Approach

The OWASP Top 10 serves as a coverage checklist to ensure the threat analysis stage systematically addresses established threat patterns. Rather than requiring a runtime tool or external skill, concise OWASP references are embedded directly into the Stage 4 prompt by the wrapper.

### 4.2 Concise Inline Reference

The Stage 4 prompt includes OWASP category names with one-line descriptions — no examples, no detailed remediation. This adds roughly 15–20 lines of context per Top 10 variant, which is negligible relative to the stage's total prompt size. Example format:

```
Use the following OWASP Top 10 (2021) as a coverage checklist to ensure your threat
analysis addresses these established patterns where relevant:

A01: Broken Access Control — restrictions on authenticated users not properly enforced
A02: Cryptographic Failures — failures related to cryptography leading to data exposure
A03: Injection — user-supplied data not validated, filtered, or sanitized
A04: Insecure Design — missing or ineffective security controls in application design
A05: Security Misconfiguration — insecure default configs, incomplete setup, open cloud storage
A06: Vulnerable and Outdated Components — using components with known vulnerabilities
A07: Identification and Authentication Failures — weak identity confirmation or session management
A08: Software and Data Integrity Failures — assumptions about software updates or data without verification
A09: Security Logging and Monitoring Failures — insufficient logging, detection, or active response
A10: Server-Side Request Forgery — fetching remote resources without validating user-supplied URLs
```

### 4.3 Conditional Variant Injection

The wrapper can conditionally include additional OWASP variants based on signals from the Stage 2 (Technical Scope) output:

- **OWASP API Security Top 10:** Injected when Stage 2 identifies REST/GraphQL/gRPC API endpoints or API gateway infrastructure
- **OWASP LLM Top 10:** Injected when Stage 2 identifies LLM/AI components, model serving infrastructure, or LLM framework dependencies (e.g., LangChain, OpenAI SDK, vector databases)

The wrapper performs lightweight keyword matching on the Stage 2 output to make this determination. This mirrors the dynamic scanner injection pattern — only relevant references are included to keep the agent focused.

### 4.4 Maintenance

OWASP references are stored as constants within the prompt template module (see Section 7.3). When OWASP updates its Top 10, updating the constants is a single-file change.

---

## 5. Dynamic Scanner Integration

The wrapper handles scanner detection; the agent handles scanner execution.

### 5.1 Detection Flow

Before invoking Stage 5, the wrapper checks for the presence of security scanners on the system:

- **Semgrep:** `which semgrep`
- **Trivy:** `which trivy`
- **Gitleaks:** `which gitleaks`

### 5.2 Dynamic Prompt Injection

For each available scanner, the wrapper appends scanner-specific instructions to the Stage 5 prompt, including basic usage examples to help the agent get started:

```
# Example injected context for Semgrep (only if detected)
Semgrep is available on this system. Run it against the codebase to augment your analysis.
Example: semgrep scan --config auto --json <target_path>
Integrate the JSON results into your vulnerability assessment.
```

Scanners that are not detected are simply omitted from the prompt entirely. This keeps the agent focused and avoids wasting context on tools it cannot use. Scanner availability is recorded in `metadata.json`.

### 5.3 Supported Scanners (MVP)

| Scanner   | Purpose                        | Detection       |
|-----------|--------------------------------|-----------------|
| Semgrep   | Static analysis patterns       | `which semgrep` |
| Trivy     | Dependency CVE scanning        | `which trivy`   |
| Gitleaks  | Secret/credential detection    | `which gitleaks` |

The scanner detection mechanism is extensible — adding a new scanner means adding a detection check and a prompt snippet.

---

## 6. CLI Interface

### 6.1 Single-Repo Mode

```bash
threatsmith /path/to/repo \
  --engine claude-code \
  --business-objectives "Protect user data, meet GDPR" \
  --security-objectives "Reduce data exfiltration risk" \
  -v
```

### 6.2 Batch Mode (Multi-Repo)

```bash
threatsmith --repos repos.txt \
  --engine codex \
  --parallel 3 \
  --auto-pr \
  -v
```

Where `repos.txt` contains one GitHub repo identifier per line (e.g., `org/repo-name`).

### 6.3 CLI Parameters

| Parameter                | Type     | Default        | Description |
|--------------------------|----------|----------------|-------------|
| `path`                   | positional | —            | Target repo path (single-repo mode) |
| `--engine`               | string   | `claude-code`  | AI engine to use (`claude-code`, `codex`) |
| `--repos`                | filepath | —              | Path to file listing GitHub repos (batch mode, mutually exclusive with positional `path`) |
| `--business-objectives`  | string   | —              | Optional business objectives to guide analysis |
| `--security-objectives`  | string   | —              | Optional security objectives to guide analysis |
| `--parallel`             | int      | 1 (sequential) | Number of parallel sessions for batch mode |
| `--auto-pr`              | flag     | false          | Auto-create PR with threat model (batch mode only) |
| `--output-dir`           | path     | `threatmodel/` | Output directory name within the repo |
| `-v` / `--verbose`       | flag     | false          | Verbose logging |

### 6.4 Batch Mode Behavior

- The wrapper clones each repo from the list into a temporary working directory
- Repos are processed sequentially by default; `--parallel N` enables parallel execution leveraging worktree support in Claude Code / Codex
- Default parallelism when `--parallel` is specified without a value: 3 concurrent sessions
- When `--auto-pr` is enabled, after all stages complete for a repo, the agent is given a final instruction to create a branch, commit the `threatmodel/` directory, push, and open a PR via `gh` CLI. This PR persists the threat model as repo context for future use in security reviews, AI coding agents, etc.
- `--auto-pr` is only available in batch mode — single-repo runs write output locally without Git operations

---

## 7. Prompt Architecture

### 7.1 Prompt Assembly

Each stage's prompt is assembled by the wrapper from three layers:

```
┌─────────────────────────────────┐
│  System Prompt (stage-specific) │  ← Stage role, methodology, output format
├─────────────────────────────────┤
│  Dynamic Context                │  ← Scanner availability, OWASP references,
│                                 │     commit hash, user objectives
├─────────────────────────────────┤
│  Prior Stage Outputs            │  ← Accumulated deliverables from
│                                 │     stages 1 through N-1
└─────────────────────────────────┘
```

### 7.2 Context Injection Format

Prior stage outputs are injected as clearly delimited sections so the agent can reference them structurally:

```
<prior_stages>
<stage_01_objectives>
[contents of 01-objectives.md]
</stage_01_objectives>

<stage_02_technical_scope>
[contents of 02-technical-scope.md]
</stage_02_technical_scope>

...
</prior_stages>
```

### 7.3 Prompt Templates

Prompt templates are self-contained within the ThreatSmith Python package. They are stored as string constants in a dedicated `prompts` subpackage, decoupled from the orchestrator logic so that prompt engineering iteration does not require changes to wrapper mechanics:

```
src/threatsmith/
  prompts/
    __init__.py
    stage_01_objectives.py       # STAGE_PROMPT = """..."""
    stage_02_technical_scope.py
    stage_03_decomposition.py
    stage_04_threat_analysis.py  # Includes OWASP reference constants
    stage_05_vulnerability.py
    stage_06_attack_modeling.py
    stage_07_risk_impact.py
    stage_08_report.py
    owasp_references.py          # OWASP_WEB_TOP_10, OWASP_API_TOP_10, OWASP_LLM_TOP_10
    scanner_snippets.py          # Per-scanner instruction templates
```

Each module exports a prompt constant and optionally a `build_prompt(context)` function that handles dynamic injection (prior stage outputs, scanner info, OWASP references). The OWASP references and scanner instruction snippets are kept in dedicated modules for single-point maintenance.

---

## 8. Scope and Phasing

### 8.1 MVP (Phase 1)

| Feature | Description |
|---------|-------------|
| Engine abstraction | Support for Claude Code and Codex via `--engine` |
| 7-stage PASTA pipeline + report consolidation | Full sequential execution with accumulated context across all 7 PASTA stages, plus a consolidation step producing `08-report.md` |
| Individual stage deliverables | Numbered markdown files in `threatmodel/` (01 through 07) |
| Consolidated report | Post-pipeline step produces `08-report.md` |
| Metadata tracking | `metadata.json` with commit hash, engine, scanners, timestamp |
| Dynamic scanner detection | Semgrep, Trivy, Gitleaks detection with prompt injection |
| OWASP reference injection | Inline OWASP Top 10 in Stage 4 with conditional API/LLM variants |
| Single-repo mode | Analyze a local repo path |
| CLI interface | All parameters from Section 6.3 (single-repo subset) |
| Prompt templates in package | Self-contained prompt constants in `src/threatsmith/prompts/` |

### 8.2 Phase 2

| Feature | Description |
|---------|-------------|
| Batch mode | `--repos` with multi-repo processing |
| Parallel execution | `--parallel N` leveraging worktree support |
| Auto-PR creation | `--auto-pr` for persisting threat models in Git |
| Incremental updates | `--update` flag that uses `git diff` against the commit hash in `metadata.json` to selectively re-run affected stages |
| Stage re-run | Ability to re-run a specific stage (e.g., `--rerun-stage 5`) with existing prior outputs |

### 8.3 Phase 3 (Future)

| Feature | Description |
|---------|-------------|
| Additional engines | Support for other AI coding agents as they emerge |
| Custom scanner plugins | User-defined scanner detection and prompt injection |
| CI/CD integration | GitHub Action / GitLab CI template for automated threat modeling on PRs |
| Threat model diff | Compare two threat model runs and surface changes |
| Interactive mode | Allow user to review and provide feedback between stages |

---

## 9. Technical Decisions

### 9.1 Decisions Made

| Decision | Rationale |
|----------|-----------|
| Python wrapper over LangGraph | Eliminates custom tool plumbing, context management, and agent orchestration complexity. AI coding agents already have code nav, file I/O, and shell access. |
| Engine abstraction from day one | Avoids vendor lock-in. Both Claude Code and Codex are supported; adding new engines requires only implementing the minimal interface. |
| Fresh session per stage with accumulated context | Maximizes per-stage token budget while preserving the structured inter-stage context that makes PASTA effective. Accumulated context actually improves agent performance by directing analysis. |
| Stage 7 as Risk and Impact Analysis (not Reporting) | Aligns with PASTA methodology. Stage 7 is analytical (risk qualification, countermeasures, residual risk). Report consolidation is a separate post-pipeline step. |
| Report consolidation as a separate step | Keeps Stage 7 focused on risk analysis. The consolidation step is lightweight (no repo access needed) and produces the unified deliverable without conflating it with analytical work. |
| Agent runs scanners directly | Simpler than wrapper-side execution and result injection. The agent can interpret results in-context and ask follow-up questions of the codebase. |
| Dynamic scanner prompt injection | Avoids polluting context with instructions for unavailable tools. Keeps the agent focused. |
| OWASP references as inline prompt constants | Eliminates the need for runtime tools, skills, or config injection. Concise category names with one-line descriptions add negligible context cost (~15–20 lines per variant). Conditional injection of API/LLM variants based on Stage 2 output keeps references targeted. |
| Drop Mermaid validation (Playwright) | LLMs have improved significantly at generating valid Mermaid syntax. Removing Playwright eliminates a heavy dependency and simplifies the stack. |
| Drop HTML report generation | Markdown is the universal format for both human readers and AI agents. HTML adds complexity without proportional value. |
| Individual stage files + consolidated report | Supports incremental updates, selective consumption, debuggability, and end-to-end review — all with minimal overhead since the consolidated report is a lightweight formatting pass. |
| Commit hash in metadata | Foundation for incremental updates without adding MVP scope. |
| Git/PR operations delegated to the agent | Claude Code and Codex can run `git` and `gh` commands natively. Keeps the wrapper thin. |
| Prompt templates self-contained in package | Decouples prompt engineering iteration from wrapper code changes. Templates live in `src/threatsmith/prompts/` as Python modules with string constants — no external files to manage or ship. |

### 9.2 Open Questions

| Question | Context |
|----------|---------|
| Token budget management | For very large repos, accumulated context from stages 1–7 plus the repo itself may approach token limits. May need a "context budget" strategy (e.g., summarizing prior stages instead of including full text) for edge cases. Monitor during MVP testing. |
| Codex CLI interface stability | Codex CLI is newer; its invocation patterns and prompt mode support should be verified during implementation. |
| Stage failure handling | If a stage fails or produces incomplete output, should the wrapper retry, skip, or abort? MVP recommendation: retry once, then abort with clear error. |
| Prompt template versioning | As prompts evolve, should the version be tracked in metadata? Useful for reproducibility but adds complexity. Defer to phase 2. |

---

## 10. Success Criteria

### 10.1 MVP Launch Criteria

- Wrapper successfully orchestrates all 7 PASTA stages plus report consolidation for a real-world repo using both Claude Code and Codex engines
- All stage deliverables are produced as individual markdown files with correct numbering (01 through 07 for PASTA stages, 08 for consolidated report)
- Consolidated report accurately reflects all stage outputs
- Dynamic scanner detection correctly identifies available/unavailable scanners and adjusts prompts accordingly
- OWASP reference injection works correctly, including conditional API/LLM variant inclusion
- metadata.json captures all required fields (commit hash, engine, scanners, timestamp)
- Output quality is comparable to or better than ThreatSmith v0.1.0 on the same target repos

### 10.2 Quality Benchmarks

- Run against ThreatSmith's own codebase as a dogfood test
- Run against at least one deliberately vulnerable application to validate vulnerability and attack modeling coverage
- Compare output quality across Claude Code and Codex engines to identify engine-specific prompt tuning needs

---

## 11. Relationship to ThreatSmith v0.1.0

This rewrite can either replace the LangGraph engine in the existing repo or start as a new repo. Recommendation: new repo (or new branch) to allow clean development without disrupting the original, with the option to archive v0.1.0 once v0.2.0 is validated.
