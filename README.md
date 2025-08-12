# ThreatSmith 🔒🤖

AI-powered secure code review and threat analysis engine that orchestrates multiple specialized agents (PASTA-inspired) to produce actionable security reports.

## Purpose

ThreatSmith helps security engineers and developers quickly understand the security posture of an application by:

- Providing systematic, multi-stage analysis (objectives, technical scope, architecture, threats, vulnerabilities, attack modeling, and consolidated reporting)
- Correlating automated scanner outputs with context-aware AI analysis
- Producing clean Markdown and HTML reports, with optional saving of raw stage-by-stage outputs

All analysis runs locally. External security scanners are optional and used only if present.

## How to use

### 1) Prerequisites

- Python 3.9+
- A model provider API key (default uses OpenAI). Set the appropriate environment variable for your provider, for example:
  - OpenAI: `OPENAI_API_KEY`
  - Google (Gemini via LangChain): `GOOGLE_API_KEY`
  - Anthropic: `ANTHROPIC_API_KEY`
- Optional external CLI tools (recommended):
  - Semgrep: `semgrep`
  - Trivy: `trivy`
  - Gitleaks: `gitleaks`

Note: If you want Mermaid diagram validation/rendering used by some agents, install Playwright browsers after setting up the virtualenv (see installation steps below).

### 2) Install locally

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/yogur/threatsmith.git
cd threatsmith

# Create and populate the project virtualenv from pyproject
uv sync

# Activate the virtualenv (created at .venv by default)
source .venv/bin/activate

# Install Playwright browser for Mermaid diagram validation/rendering
python -m playwright install --with-deps chromium
```

Optionally install the external scanners (refer to each tool’s docs):

- [Semgrep](https://github.com/semgrep/semgrep)
- [Trivy](https://github.com/aquasecurity/trivy)
- [Gitleaks](https://github.com/gitleaks/gitleaks)

### 3) Run the CLI

You can run via the installed entry point or directly with Python.

```bash
# Using entry point
threatsmith /path/to/project \
  --model openai:gpt-4.1 \
  --business_objectives "Protect user data, meet GDPR" \
  --security_objectives "Reduce data exfiltration risk" \
  --output_dir ./output \
  -v

# Or run directly
python -m threatsmith.main /path/to/project --model anthropic:claude-sonnet-4-0 -v --save-stage-outputs
```

Flags:

- `path` (positional): Target project path to analyze
- `--model`: Model identifier in the format `provider:model-id`.
  - Examples: `openai:gpt-4.1`, `anthropic:claude-sonnet-4-0`, `google_genai:gemini-2.0-flash`
- `--business_objectives`: Optional business goals to guide analysis
- `--security_objectives`: Optional security goals to guide analysis
- `--output_dir`: Directory for reports (default: `./output`)
- `-v/--verbose`: Verbose logging
- `--save-stage-outputs`: Save a second markdown with raw outputs from each analysis stage

Outputs (in `--output_dir`):

- Final report: `threat_analysis_report_YYYYMMDD_HHMMSS.md`
- Final report (HTML): `threat_analysis_report_YYYYMMDD_HHMMSS.html`
- Stage outputs (if enabled): `threat_analysis_stage_outputs_YYYYMMDD_HHMMSS.md`

Scanner behavior:

- If Semgrep/Trivy/Gitleaks are installed, their results are integrated
- If unavailable, the pipeline continues and notes unavailable scanners

## How it works (brief)

At the core is a LangGraph state machine that orchestrates specialized agents. The pipeline runs in sequence and shares state between stages:

1. Objectives Agent: establishes business context, data sensitivity, and compliance indicators
2. Technical Scope Agent: inventories stack, dependencies, infrastructure
3. Application Decomposition Agent: maps architecture, entry points, trust boundaries, and data flows; validates Mermaid diagrams
4. Threat Analysis Agent: performs STRIDE-driven, component-wide threat identification, cross-referencing OWASP Top 10
5. Vulnerability Analysis Agent: correlates Semgrep/Trivy/Gitleaks findings with context-driven manual analysis; scores and classifies
6. Attack Modeling Agent: builds realistic attack scenarios and Mermaid attack trees with feasibility assessments
7. Reporting Agent: consolidates all previous outputs into a clean, professional final report (optionally also saves stage outputs)

Key implementation details:

- CLI: `src/threatsmith/main.py` defines the interface and arguments
- Orchestrator: `src/threatsmith/orchestrator.py` wires agents into a `StateGraph` and manages execution and saving reports
- Tools:
  - Code ingestion via `gitingest` with safe path constraints (`src/threatsmith/tools/code_ingestor.py`)
  - Mermaid validation/rendering via Playwright (`src/threatsmith/tools/mermaid_diagramming.py`)
  - OWASP Top 10 reference toolkit (`src/threatsmith/tools/owasp_top_ten.py`)
  - External scanners wrapped with graceful error handling (`src/threatsmith/scanners/*.py`)
- Reporting: Markdown and HTML generation with Mermaid support (`src/threatsmith/utils/reporting.py`)

### Model selection

- Uses LangChain’s `init_chat_model` with provider-style model IDs (e.g., `openai:...`, `anthropic:...`, `google_genai:...`). Ensure the corresponding API key is set in your environment.

#### Supported model providers and required environment variables

- **OpenAI**
  - **Env var**: `OPENAI_API_KEY`
  - **Example model**: `openai:gpt-4.1`
- **Anthropic**
  - **Env var**: `ANTHROPIC_API_KEY`
  - **Example model**: `anthropic:claude-sonnet-4-0`
- **Google (Gemini via LangChain)**
  - **Env var**: `GOOGLE_API_KEY`
  - **Example model**: `google_genai:gemini-2.5-flash`

### Diagram rendering

- Mermaid validation/rendering requires Playwright browsers (`python -m playwright install --with-deps chromium`).

### External scanners

- Semgrep/Trivy/Gitleaks integrations are optional; if not installed, the pipeline proceeds and notes unavailable scanners.

