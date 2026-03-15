```
 ████████╗ ██╗  ██╗ ██████╗  ███████╗  █████╗  ████████╗ ███████╗ ███╗   ███╗ ██╗ ████████╗ ██╗  ██╗
 ╚══██╔══╝ ██║  ██║ ██╔══██╗ ██╔════╝ ██╔══██╗ ╚══██╔══╝ ██╔════╝ ████╗ ████║ ██║ ╚══██╔══╝ ██║  ██║
    ██║    ███████║ ██████╔╝ █████╗   ███████║    ██║    ███████╗ ██╔████╔██║ ██║    ██║    ███████║
    ██║    ██╔══██║ ██╔══██╗ ██╔══╝   ██╔══██║    ██║    ╚════██║ ██║╚██╔╝██║ ██║    ██║    ██╔══██║
    ██║    ██║  ██║ ██║  ██║ ███████╗ ██║  ██║    ██║    ███████║ ██║ ╚═╝ ██║ ██║    ██║    ██║  ██║
    ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝    ╚═╝    ╚══════╝ ╚═╝     ╚═╝ ╚═╝    ╚═╝    ╚═╝  ╚═╝
```

# ThreatSmith 🔒🤖

ThreatSmith is an AI-powered PASTA threat modeling engine that automates the entire PASTA pipeline. It runs each stage as a fresh AI coding agent session, assembles prompts with accumulated context from prior stages, auto-detects available security scanners, and validates that each stage produces its expected deliverable. The result is a complete, structured threat model generated directly from your codebase.

**No API keys. No separate billing. No token budgets to manage.** If you have a `Claude Code` or `Codex` subscription, you already have everything you need. Point ThreatSmith at a repository and get a full threat model.

### What is PASTA?

[PASTA (Process for Attack Simulation and Threat Analysis)](https://handbook.gitlab.com/handbook/security/product-security/security-platforms-architecture/application-security/threat-modeling/#pasta-stages) is a 7-stage, risk-centric methodology that produces structured security artifacts: data flow diagrams, threat inventories, vulnerability assessments, attack trees, and prioritized remediation roadmaps. It is thorough, but the manual effort involved makes full adoption rare.

## Use Cases

- **Persist threat models in Git as context for AI-powered secure code review.** Commit the `threatmodel/` directory to your repository. When AI coding agents review PRs or audit code, they can reference the threat model for context on trust boundaries, known vulnerabilities, and attack surfaces.
- **Give AI coding agents security context to write secure code.** With the threat model in the repo, agents writing new features can consult it to understand data sensitivity classifications, required security controls, and known attack vectors before producing code.
- **Onboard security engineers to unfamiliar codebases.** The 7-stage output provides a structured, security-focused overview of architecture, data flows, threats, and vulnerabilities without manually reading the entire codebase.
- **Triage and prioritize remediation.** Stage 7 produces a P0-P3 remediation roadmap ranked by risk reduction vs. implementation effort, giving engineering teams a ready-made security backlog.

## How It Works

```
┌────────────────┐     ┌──────────────────────┐     ┌──────────────────┐
│  CLI           │────>│  Orchestrator        │────>│  AI Coding Agent │
│                │     │                      │     │                  │
│  threatsmith   │     │  - Stage sequencing  │     │  Claude Code /   │
│  /path/to/repo │     │  - Prompt assembly   │     │  Codex           │
│  --engine      │     │  - Context passing   │     │                  │
│                │     │  - Scanner detection │     │  - Code nav      │
│                │     │  - Output validation │     │  - File I/O      │
└────────────────┘     └──────────────────────┘     │  - Shell exec    │
                                                    │  - Reasoning     │
                                                    └──────────────────┘
```

ThreatSmith runs a sequential pipeline of 7 PASTA stages plus a report consolidation step. Each stage executes as a fresh agent session but receives all prior stage outputs as structured context. This mirrors how a security engineer works through PASTA: read the prior findings, then produce the next deliverable.

Currently supports Claude Code (`--engine claude-code`) and Codex (`--engine codex`). Adding a new engine requires implementing a single method: `execute(prompt, working_directory) -> exit_code`.

| Stage | Name | Output |
|-------|------|--------|
| 1 | Define Objectives | Business objectives, data sensitivity, compliance requirements |
| 2 | Define Technical Scope | Technology stack, dependencies, supply chain, deployment |
| 3 | Application Decomposition | Architecture, data flow diagrams (Mermaid), trust boundaries |
| 4 | Threat Analysis | STRIDE analysis, attack scenarios, OWASP cross-referencing |
| 5 | Vulnerability Analysis | Scanner results, CVSS scoring, CWE/CVE enumeration |
| 6 | Attack Modeling | Attack trees (Mermaid), MITRE ATT&CK mapping, exploit paths |
| 7 | Risk and Impact Analysis | Risk qualification, countermeasures, P0-P3 remediation roadmap |
| | | |
| 8 | Report Consolidation | Executive summary combining all stage outputs (not a PASTA stage) |

### Context Accumulation

Each stage builds on all prior stages. Stage N receives the outputs of stages 1 through N-1, injected as structured XML-delimited sections in the prompt. This accumulated context directs the agent's analysis, reducing blind codebase exploration and improving output quality.

## Installation

### Prerequisites

- Python 3.12+
- One of the supported AI coding agents installed and authenticated:
  - `Claude Code` for the claude-code engine
  - `Codex` for the codex engine

### Install

```bash
# With pip
pip install threatsmith

# With uv
uv tool install threatsmith

# With pipx (no virtual environment needed)
pipx install threatsmith

# With uvx (no virtual environment needed)
uvx install threatsmith
```

## Quick Start

```bash
threatsmith /path/to/your/repo
```

This runs the full 7-stage PASTA pipeline using Claude Code (the default engine) and writes all deliverables to `threatmodel/` inside the target repository.

To use a different engine or provide objectives to guide the analysis:

```bash
threatsmith /path/to/your/repo \
  --engine codex \
  --business-objectives "Protect user PII, meet GDPR requirements" \
  --security-objectives "Prevent data exfiltration" \
  -v
```

## Scanner Integration

ThreatSmith automatically detects security scanners on your system before running the pipeline. When a scanner is found, stage-specific instructions are injected into the Stage 5 (Vulnerability Analysis) prompt so the agent knows to run it and incorporate the results.

| Scanner | Purpose | Detection |
|---------|---------|-----------|
| Semgrep | Static analysis patterns | `which semgrep` |
| Trivy | Dependency CVE scanning | `which trivy` |
| Gitleaks | Secret/credential detection | `which gitleaks` |

Scanners that are not detected are omitted from the prompt entirely. Scanner availability is recorded in `metadata.json` for traceability.

## Output Structure

All deliverables are written to a `threatmodel/` directory (configurable via `--output-dir`) at the target repository root:

```
threatmodel/
  metadata.json                    # Run metadata (engine, commit, scanners, timestamp)
  01-objectives.md                 # Stage 1: Business objectives and data sensitivity
  02-technical-scope.md            # Stage 2: Technology stack and dependencies
  03-application-decomposition.md  # Stage 3: Architecture, DFDs, trust boundaries
  04-threat-analysis.md            # Stage 4: Threat identification and attack scenarios
  05-vulnerability-analysis.md     # Stage 5: Vulnerability findings and CVSS scoring
  06-attack-modeling.md            # Stage 6: Attack trees and exploitation paths
  07-risk-and-impact-analysis.md   # Stage 7: Risk qualification and remediation roadmap
  08-report.md                     # Consolidated executive report
```

Individual stage files are preserved alongside the consolidated report. This supports selective consumption (a developer fixing an auth issue only needs stages 4-5), debuggability (re-examine a single stage's output), and granular review by security teams.

## CLI Reference

```
threatsmith <path> [OPTIONS]
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | positional | required | Path to the target repository |
| `--engine` | string | `claude-code` | AI engine to use (`claude-code` or `codex`) |
| `--business-objectives` | string | — | Business objectives to guide the analysis |
| `--security-objectives` | string | — | Security objectives to guide the analysis |
| `--output-dir` | string | `threatmodel/` | Output directory for deliverables (relative to target repo) |
| `-v` / `--verbose` | flag | off | Enable verbose (debug-level) logging |

## Roadmap

- **Batch mode.** Process multiple repositories from a file list (`--repos repos.txt`) with configurable parallelism (`--parallel N`).
- **Auto-PR creation.** Automatically commit the `threatmodel/` directory, push a branch, and open a pull request via `gh` CLI after analysis completes.
- **Incremental updates.** Use `git diff` against the commit hash in `metadata.json` to selectively re-run only the stages affected by code changes.
- **Stage re-run.** Re-run a specific stage (e.g., `--rerun-stage 5`) using existing prior stage outputs without re-running the entire pipeline.
- **Resume from stage.** Resume a failed or interrupted pipeline run from the stage where it stopped.
- **CI/CD integration.** GitHub Action and GitLab CI templates for automated threat modeling on pull requests.
- **Threat model diff.** Compare two threat model runs and surface what changed between them.

## License

MIT License.
