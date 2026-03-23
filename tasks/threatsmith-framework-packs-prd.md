# ThreatSmith Framework Packs — Product Requirements Document

**Author:** Abed
**Date:** March 2026
**Status:** Complete (v0.3.0) — LINDDUN Pro and MAESTRO deferred to future release
**Builds on:** ThreatSmith v0.2.0 (sequential PASTA pipeline with Claude Code / Codex engines)

---

## 1. Overview

### 1.1 Release Goal

ThreatSmith currently runs a single methodology: PASTA. This release introduces a framework pack architecture that supports multiple threat modeling methodologies as pluggable, self-contained modules. The orchestrator becomes methodology-agnostic, and users choose their framework via a `--framework` CLI flag. Two frameworks ship in v0.3.0; two are deferred to future release:

- **4QF+STRIDE** — Four Question Framework with STRIDE. Lightweight, fast, good default for most codebases. *(shipped)*
- **PASTA** — Full 7-stage risk-centric analysis. Already implemented, migrated into the pack structure. *(shipped)*
- **LINDDUN Pro** — Systematic privacy threat modeling. For codebases handling personal data under GDPR, HIPAA, or similar regulations. *(deferred to future release)*
- **MAESTRO** — AI/ML system threat modeling. For codebases that include models, training pipelines, inference services, or autonomous agents. *(deferred to future release)*

### 1.2 Scope

**In scope (shipped in v0.3.0):**

- Framework pack abstraction (data model, registry, discovery)
- Orchestrator and assembler refactor to be framework-agnostic
- Migration of existing PASTA prompts into the pack structure
- 4QF+STRIDE framework pack with stage prompts and reference lists
- Scanner integration as a framework-configurable concern
- CLI `--framework` flag (default: `stride-4q`)
- Metadata framework tracking

**deferred to future release:**

- LINDDUN Pro framework pack (US-F06, US-F17–US-F23, US-F35)
- MAESTRO framework pack (US-F07, US-F24–US-F31, US-F36)
- `linddun_catalogue.py` and `mitre_atlas.py` reference constants

**Out of scope (all versions):**

- Custom user-defined frameworks
- Framework-specific scanner plugins (e.g., privacy scanners for LINDDUN, AI-specific scanners for MAESTRO)
- Framework mixing (running STRIDE for quick triage then PASTA for deep dive in a single invocation)

### 1.3 Design Principles

Carried forward from prior releases, with one addition:

- **Leverage, don't rebuild.** The wrapper orchestrates; agents do the analysis.
- **Stage isolation with accumulated context.** Fresh session per stage, prior outputs as context.
- **Deliverables over conversation.** Validate files, don't parse agent dialogue.
- **Extensibility by design.** New engines, scanners, stages, and now frameworks without structural changes.
- **Repeatability by default.** Runs are reproducible from configuration alone.
- **Methodology as configuration, not code.** *(New)* Adding a new threat modeling framework requires defining stages, writing prompts, and registering the pack. It does not require changes to the orchestrator, assembler, CLI, or any other wrapper infrastructure.

---

## 2. Architecture

### 2.1 Framework Pack Data Model

A framework pack is a self-contained definition of a threat modeling methodology. It provides everything the orchestrator needs to run the pipeline without knowing which methodology is executing.

```python
@dataclass
class StageSpec:
    number: int                    # Stage number (1-based, sequential)
    name: str                      # Human-readable name (e.g., "Threat Identification")
    output_file: str               # Expected output filename (e.g., "02-threats.md")
    build_prompt: Callable         # Reference to the stage's build_prompt(context) function

@dataclass
class FrameworkPack:
    name: str                      # Machine identifier (e.g., "stride-4q", "pasta")
    display_name: str              # Human-readable name (e.g., "4QF + STRIDE")
    description: str               # One-line description for --help and metadata
    stages: list[StageSpec]        # Ordered list of analysis stages
    report_stage: StageSpec        # Consolidation step (always runs last)
    scanner_stages: list[int]      # Which stage numbers receive scanner context
    reference_sets: dict[int, list[str]]  # Stage number -> list of reference constant names
```

```python
@dataclass
class StageContext:
    """Generic context passed to any stage's build_prompt function."""
    user_objectives: dict[str, str] | None = None
    prior_outputs: dict[str, str] = field(default_factory=dict)
    scanners_available: list[str] | None = None
    references: list[str] = field(default_factory=list)
```

All `build_prompt` functions across all frameworks use the same `StageContext` dataclass:
```python
def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
```

The orchestrator iterates `pack.stages`, then runs `pack.report_stage`. It never references stage numbers or names directly — it follows the pack's definition.

### 2.2 Framework Registry

A registry maps framework identifiers to pack instances:

```python
FRAMEWORKS = {
    "stride-4q": build_stride_4q_pack(),
    "pasta": build_pasta_pack(),
    "linddun": build_linddun_pack(),
    "maestro": build_maestro_pack(),
}

def get_framework(name: str) -> FrameworkPack:
    if name not in FRAMEWORKS:
        raise ValueError(f"Unknown framework: {name}. Available: {list(FRAMEWORKS.keys())}")
    return FRAMEWORKS[name]
```

The CLI calls `get_framework(args.framework)` and passes the pack to the orchestrator. Adding a new framework means writing a pack builder function and registering it.

### 2.3 Directory Structure

Framework code is organized under `frameworks/`. The assembler is a top-level module. The `prompts/` package has been eliminated.

```
src/threatsmith/
  assembler.py                             # Framework-agnostic prompt assembly (top-level)
  orchestrator.py                          # Framework-agnostic: iterates pack.stages
  frameworks/
    __init__.py                            # Public API: re-exports from types.py, triggers _built_in
    types.py                               # FrameworkPack, StageSpec, StageContext, _REGISTRY, register/get/list
    _built_in.py                           # Imports pack builders, calls register_framework()
    references/                            # Shared reference constants
      __init__.py                          # Re-exports evaluate_reference_conditions + keywords
      conditions.py                        # evaluate_reference_conditions()
      owasp.py                             # OWASP_WEB/API/LLM/MOBILE_TOP_10
      scanner_snippets.py                  # SCANNER_SNIPPETS dict
      stride_categories.py                 # STRIDE_CATEGORIES
      linddun_catalogue.py                 # LINDDUN_THREAT_TYPES, LINDDUN_DFD_PATTERNS (deferred to future release)
      mitre_atlas.py                       # MITRE_ATLAS_TECHNIQUES (deferred to future release)
    pasta/
      __init__.py                          # Exports build_pasta_pack
      _pack.py                             # build_pasta_pack() implementation
      stage_01_objectives.py ... stage_08_report.py
    stride_4q/
      __init__.py                          # Exports build_stride_4q_pack
      _pack.py                             # build_stride_4q_pack() implementation
      stage_01_system_model.py ... stage_05_report.py
    linddun/
      __init__.py                          # Empty package marker (deferred to future release)
    maestro/
      __init__.py                          # Empty package marker (deferred to future release)
```

Shared reference modules (`owasp.py`, `scanner_snippets.py`) are at the `frameworks/references/` level since they may be consumed by multiple frameworks. Framework-specific references (`linddun_catalogue.py`, `mitre_atlas.py`) are also at this level for consistency and potential cross-framework reuse.

### 2.4 Scanner Integration Model

Scanner detection remains global — `detect_scanners()` runs once before the pipeline regardless of framework. Each framework pack declares which of its stages receive scanner context via the `scanner_stages` list. The assembler injects scanner snippets into those stages and omits them from all others.

| Framework | Scanner Stages | Rationale |
|-----------|---------------|-----------|
| 4QF+STRIDE | Stage 2 (Threat Identification) | No dedicated vulnerability stage; scanner output enriches threat identification |
| PASTA | Stage 5 (Vulnerability Analysis) | Dedicated vulnerability stage, same as current behavior |
| LINDDUN Pro | None (MVP) | Privacy scanners are a future addition; traditional scanners are less relevant to privacy analysis |
| MAESTRO | Stage 4 (Vulnerability Analysis) | Dependency and code scanning is relevant to AI system supply chain analysis |

The scanner snippet mechanism is unchanged. Framework packs simply declare where snippets land.

---

## 3. Framework Specifications

### 3.1 4QF+STRIDE (Default)

The Four Question Framework provides a streamlined threat modeling structure: what are we working on, what can go wrong, what are we going to do about it, and did we do a good enough job. STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) provides the systematic threat categorization within the "what can go wrong" stage.

**Identifier:** `stride-4q`  
**Stages:** 4 analysis stages + 1 report consolidation

| Stage | Name | Output File | Focus |
|-------|------|-------------|-------|
| 1 | System Model | `01-system-model.md` | Application purpose, scope, and architecture. Technology stack, data flows, actors, assets, trust boundaries. Mermaid DFDs showing components and data in motion. Entry points, external dependencies, and deployment context. |
| 2 | Threat Identification | `02-threat-identification.md` | Systematic STRIDE analysis per component and data flow identified in Stage 1. Threat scenarios for each STRIDE category with attacker motivation and capability assessment. OWASP Top 10 cross-referencing for coverage validation. Scanner results integration (when available). Threat prioritization by likelihood and impact. |
| 3 | Mitigations | `03-mitigations.md` | Countermeasure identification for each threat. Existing controls assessment (what is already in place). Gap analysis between current and required controls. Implementation recommendations with effort estimates. Residual risk after mitigation. |
| 4 | Validation | `04-validation.md` | Coverage verification: are all components from Stage 1 addressed? Are all STRIDE categories covered? Mitigation completeness: do proposed mitigations address all high-priority threats? Remaining gaps and accepted risks with justification. Recommended next steps and review cadence. |
| 5 | Report | `05-report.md` | Executive summary consolidating all stages. No new analysis. |

**Reference Sets:**

| Stage | References |
|-------|-----------|
| 2 | STRIDE categories (always), OWASP Web Top 10 (always), OWASP API Top 10 (conditional on Stage 1 API detection), OWASP LLM Top 10 (conditional on Stage 1 LLM detection) |

**Scanner Stages:** Stage 2

---

### 3.2 PASTA (Existing)

Migrated into the pack structure with no changes to prompt content or behavior. The only change is organizational: prompt modules move from `prompts/stage_XX_*.py` to `prompts/pasta/stage_XX_*.py`.

**Identifier:** `pasta`  
**Stages:** 7 analysis stages + 1 report consolidation

Stage structure, prompt content, OWASP reference injection, and scanner integration remain identical to the current v0.2.0 implementation. See the v0.2.0 PRD for full details.

**Reference Sets:**

| Stage | References |
|-------|-----------|
| 4 | OWASP Web Top 10 (always), OWASP API Top 10 (conditional), OWASP LLM Top 10 (conditional) |

**Scanner Stages:** Stage 5

---

### 3.3 LINDDUN Pro *(deferred to future release)*

LINDDUN Pro is a systematic privacy threat modeling methodology. It identifies threats to personal data across seven categories: Linking, Identifying, Non-repudiation, Detecting, Data Disclosure, Unawareness, and Non-compliance. Each category targets a specific privacy property (unlinkability, anonymity, plausible deniability, undetectability, confidentiality, content awareness, and policy compliance respectively).

**Identifier:** `linddun`  
**Stages:** 5 analysis stages + 1 report consolidation

| Stage | Name | Output File | Focus |
|-------|------|-------------|-------|
| 1 | System Context and Data Inventory | `01-system-context.md` | Application purpose and scope with a privacy lens. Comprehensive personal data inventory: what personal data is collected, processed, stored, and transmitted. Data subjects identification (users, employees, third parties). Data processing purposes and legal basis for each. Retention policies and data lifecycle. Regulatory context (GDPR, HIPAA, CCPA, etc.) derived from codebase signals (data models, config, documentation). Third-party data sharing and processor relationships. |
| 2 | Data Flow Decomposition | `02-data-flow.md` | Privacy-annotated data flow diagrams (Mermaid) showing personal data in motion and at rest. Each data flow annotated with: data types, data subjects affected, processing purpose, encryption status, retention. Trust boundaries with privacy significance (where data crosses jurisdictions, leaves organizational control, or is shared with third parties). Data minimization assessment: is more data collected than necessary for stated purposes. Storage locations and access patterns for personal data. |
| 3 | Threat Elicitation | `03-threat-elicitation.md` | Systematic application of all seven LINDDUN categories to each DFD element from Stage 2. For each DFD element (process, data store, data flow, external entity), evaluate: Linking (can records be connected across contexts?), Identifying (can a data subject be identified?), Non-repudiation (can a data subject deny involvement?), Detecting (can personal data processing be detected?), Data Disclosure (can personal data be accessed by unauthorized parties?), Unawareness (are data subjects unaware of data processing?), Non-compliance (does processing violate regulatory requirements?). Threat scenarios with concrete attack/violation narratives. Cross-reference with LINDDUN threat tree catalogue for systematic coverage. |
| 4 | Threat Prioritization | `04-threat-prioritization.md` | Risk assessment for each elicited privacy threat. Likelihood based on: technical feasibility, attacker motivation, existing controls. Impact based on: number of data subjects affected, sensitivity of data, regulatory consequences, reputational damage. Risk rating using a structured scale. Grouping of threats by risk level for mitigation planning. Identification of threats that interact or amplify each other. |
| 5 | Mitigation Selection | `05-mitigation.md` | Privacy enhancing technologies (PETs) mapped to each high and medium risk threat. Mitigation strategies organized by LINDDUN category using established privacy patterns: data minimization, anonymization, pseudonymization, access control, encryption, transparency mechanisms, consent management, purpose limitation enforcement. Gap analysis: current controls vs. required controls. Implementation recommendations with effort and complexity estimates. Residual privacy risk after mitigation. Data Protection Impact Assessment (DPIA) considerations where applicable. |
| 6 | Report | `06-report.md` | Executive summary with privacy risk posture. Consolidated findings across all stages. No new analysis. |

**Reference Sets:**

| Stage | References |
|-------|-----------|
| 3 | LINDDUN threat type catalogue (always) |
| 5 | LINDDUN mitigation strategies / privacy patterns (always) |

**Scanner Stages:** None in MVP. Traditional security scanners (Semgrep, Trivy, Gitleaks) are of limited relevance to privacy threat modeling. Future versions may integrate privacy-specific scanners (e.g., Privado for data flow analysis, custom PII detection rules).

---

### 3.4 MAESTRO *(deferred to future release)*

MAESTRO focuses on threats specific to AI and machine learning systems: model integrity, training data security, inference pipeline attacks, agent autonomy risks, and AI supply chain vulnerabilities. It draws on MITRE ATLAS (Adversarial Threat Landscape for AI Systems) for threat technique classification and OWASP LLM Top 10 for coverage validation.

**Identifier:** `maestro`  
**Stages:** 6 analysis stages + 1 report consolidation

| Stage | Name | Output File | Focus |
|-------|------|-------------|-------|
| 1 | AI System Profiling | `01-ai-system-profiling.md` | AI/ML system inventory: models, training pipelines, inference services, agent frameworks, vector databases, embedding stores. Model metadata: architecture type, training data sources, fine-tuning approach, model provenance. Agent capabilities: tool access, autonomy level, decision scope, human-in-the-loop controls. Integration points: how AI components interact with traditional application components. Data sensitivity: training data classification, user input handling, output sensitivity. Business context: what decisions the AI system influences, consequences of AI failure or manipulation. |
| 2 | Architecture and Data Flow | `02-architecture.md` | AI-specific architecture decomposition: model serving infrastructure, training pipeline components, data preprocessing, feature stores, model registries, orchestration layers. Data flow diagrams (Mermaid) covering: training data pipeline (collection, preprocessing, storage, model training), inference pipeline (input, preprocessing, model invocation, postprocessing, output), agent execution flow (prompt construction, tool calls, context management, output handling). Trust boundaries specific to AI: model boundary (what the model can access), agent boundary (what the agent can do), training boundary (who can influence training data), deployment boundary (who can deploy model updates). Supply chain mapping: model sources (commercial APIs, open-source models, fine-tuned variants), framework dependencies, dataset provenance. |
| 3 | Threat Identification | `03-threat-identification.md` | Systematic threat analysis using MITRE ATLAS techniques across all AI components. Threat categories covering: prompt injection (direct and indirect), training data poisoning, model extraction and theft, model inversion (data reconstruction from model), adversarial inputs (evasion attacks), agent manipulation (goal hijacking, tool misuse), supply chain attacks (compromised models, backdoored training data, malicious dependencies), information leakage (training data memorization, system prompt extraction), denial of service (model resource exhaustion, inference bombing), unauthorized capability access (privilege escalation through agent tools). OWASP LLM Top 10 cross-referencing for coverage validation. Threat scenarios with concrete attack narratives specific to the codebase's AI components. |
| 4 | Vulnerability Analysis | `04-vulnerability-analysis.md` | Assessment of AI-specific vulnerabilities in the codebase. Input validation: are prompts, user inputs, and tool outputs sanitized before reaching the model? Output filtering: are model outputs validated, filtered, or constrained before action? Agent guardrails: are tool calls scoped, rate-limited, and authorization-checked? Training pipeline security: is training data validated, is the pipeline access-controlled? Model access controls: who can query, fine-tune, or replace models? Dependency analysis: known vulnerabilities in ML frameworks, model serving libraries, and agent toolkits. Scanner results integration (Semgrep for code patterns, Trivy for dependency CVEs, Gitleaks for exposed API keys and model credentials). CVSS scoring and CWE enumeration where applicable. |
| 5 | Attack Modeling | `05-attack-modeling.md` | Attack trees (Mermaid) for high-priority threats from Stage 3. Multi-stage attack paths that chain AI-specific and traditional vulnerabilities. MITRE ATLAS technique mapping per attack path with tactic/technique IDs. Feasibility assessment: required attacker skill, access level, tooling, and cost. Impact assessment: what a successful attack achieves (data exfiltration, model manipulation, unauthorized actions, service disruption). Focus on attack paths that traverse AI and non-AI components (e.g., traditional SSRF enabling indirect prompt injection via fetched content). |
| 6 | Risk and Mitigation | `06-risk-mitigation.md` | Risk qualification for each attack path. AI-specific countermeasures: input/output guardrails, prompt hardening, model access controls, training pipeline integrity checks, agent sandboxing, tool authorization policies, output content filtering, model monitoring and anomaly detection. Traditional countermeasures applied to AI context: network segmentation for model serving, secrets management for API keys, dependency pinning for ML libraries. Prioritized remediation roadmap (P0-P3) with implementation effort, risk reduction, and coverage breadth. Residual risk assessment after proposed mitigations. |
| 7 | Report | `07-report.md` | Executive summary with AI risk posture. Consolidated findings across all stages. No new analysis. |

**Reference Sets:**

| Stage | References |
|-------|-----------|
| 3 | MITRE ATLAS techniques (always), OWASP LLM Top 10 (always) |
| 5 | MITRE ATLAS techniques (always) |

**Scanner Stages:** Stage 4

---

## 4. Reference Constants

### 4.1 Existing (Relocated)

The following constants move from `prompts/owasp_references.py` and `prompts/scanner_snippets.py` to `frameworks/references/`:

- `owasp.py`: `OWASP_WEB_TOP_10`, `OWASP_API_TOP_10`, `OWASP_LLM_TOP_10`, `OWASP_MOBILE_TOP_10`
- `scanner_snippets.py`: `SEMGREP_SNIPPET`, `TRIVY_SNIPPET`, `GITLEAKS_SNIPPET`, `SCANNER_SNIPPETS`

### 4.2 New Constants

**`stride_categories.py`** — STRIDE category definitions with one-line descriptions, used as a reference checklist in 4QF+STRIDE Stage 2:

```
S: Spoofing — pretending to be something or someone other than yourself
T: Tampering — modifying something on disk, network, or in memory
R: Repudiation — claiming you didn't do something or were not responsible
I: Information Disclosure — providing information to someone not authorized to see it
D: Denial of Service — absorbing resources needed to provide service
E: Elevation of Privilege — allowing someone to do something they are not authorized to do
```

**`linddun_catalogue.py`** *(deferred to future release)* — LINDDUN threat type definitions with privacy property mapping. Contains the seven categories with descriptions and the privacy property each protects. Also includes a concise reference of common privacy threat patterns per DFD element type (process, data store, data flow, external entity) to guide the agent's systematic elicitation.

**`mitre_atlas.py`** *(deferred to future release)* — MITRE ATLAS technique reference for AI/ML threats. Concise listing of ATLAS tactics and high-relevance techniques with IDs and one-line descriptions. Covers: reconnaissance, resource development, initial access (to ML systems), ML attack staging, ML model access, exfiltration, and impact. Kept concise following the same approach as OWASP references — category names and one-liners, not full technique writeups.

### 4.3 Maintenance

Each reference module is a single file with string constants. Updating a reference (e.g., when OWASP publishes a new Top 10) is a single-file change that does not touch the orchestrator, assembler, or any prompt templates. This is identical to the existing approach, just applied across more reference sets.

---

## 5. Refactor Details

### 5.1 Orchestrator Changes

The orchestrator currently has a hardcoded stage 1-8 loop. The refactor replaces this with iteration over the framework pack's stage list:

**Before (v0.2.0):**
```python
for stage_num in range(1, 9):
    prompt = assemble_prompt(stage_num, ...)
    engine.execute(prompt, working_dir)
    validate_output(output_dir, stage_num)
```

**After:**
```python
for stage in pack.stages:
    prompt = pack_assembler.assemble(stage, prior_outputs, ...)
    engine.execute(prompt, working_dir)
    validate_output(output_dir, stage.output_file)

# Report consolidation
prompt = pack_assembler.assemble(pack.report_stage, prior_outputs, ...)
engine.execute(prompt, working_dir)
validate_output(output_dir, pack.report_stage.output_file)
```

The orchestrator receives the `FrameworkPack` at construction and does not import or reference any framework-specific modules.

### 5.2 Assembler Changes

The assembler currently maps stage numbers to prompt modules using hardcoded imports. The refactor eliminates this mapping entirely — each `StageSpec` in the pack carries a reference to its own `build_prompt` function. The assembler's job simplifies to:

1. Build the context dict (prior outputs, scanner info, references, user objectives).
2. Determine which references to inject (from `pack.reference_sets[stage.number]`).
3. Determine whether to inject scanner context (from `pack.scanner_stages`).
4. Call `stage.build_prompt(context)`.

The assembler no longer needs to know how many stages exist or what they're called.

### 5.3 Output Validation Changes

The orchestrator currently validates output by checking for files named `01-objectives.md` through `08-report.md`. The refactor validates against `stage.output_file` from the pack definition. This naturally supports frameworks with different stage counts and naming conventions.

### 5.4 Metadata Changes

`metadata.json` gains a `framework` field:

```json
{
  "framework": "stride-4q",
  "framework_display_name": "4QF + STRIDE",
  "stages_completed": 5,
  ...
}
```

### 5.5 Config File Changes

`.threatsmith.yml` gains a `framework` field:

```yaml
framework: pasta
engine: claude-code
output_dir: threatmodel/
```

---

## 6. CLI Changes

### 6.1 New Flag

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--framework` | string | `stride-4q` | Threat modeling framework to use |

Available values: `stride-4q`, `pasta`, `linddun`, `maestro`.

### 6.2 Framework Listing

```bash
threatsmith --list-frameworks
```

Prints available frameworks with descriptions:

```
Available frameworks:
  stride-4q   4QF + STRIDE — lightweight threat model with STRIDE categorization (default)
  pasta       PASTA — 7-stage risk-centric threat analysis
  linddun     LINDDUN Pro — systematic privacy threat modeling
  maestro     MAESTRO — AI/ML system threat modeling
```

### 6.3 Backward Compatibility

The `--framework` flag defaults to `stride-4q`. Users who want the previous default (PASTA) can set `framework: pasta` in `.threatsmith.yml` or pass `--framework pasta` on the CLI.

### 6.4 Interaction with Stage Re-Run

`--rerun-stage` validates stage numbers against the selected framework's stage count. Running `--rerun-stage 7` with `--framework stride-4q` (which has 4+1 stages) produces an error. The error message includes the valid stage range for the selected framework.

---

## 7. Conditional Reference Injection

### 7.1 Mechanism

The conditional OWASP injection logic from PASTA Stage 4 (inject API Top 10 when API keywords detected in prior output, inject LLM Top 10 when LLM keywords detected) is generalized into a reusable mechanism.

Each entry in `pack.reference_sets` can be marked as conditional:

```python
reference_sets = {
    2: [
        {"ref": "STRIDE_CATEGORIES", "condition": "always"},
        {"ref": "OWASP_WEB_TOP_10", "condition": "always"},
        {"ref": "OWASP_API_TOP_10", "condition": "api_detected"},
        {"ref": "OWASP_LLM_TOP_10", "condition": "llm_detected"},
    ]
}
```

The assembler evaluates conditions against prior stage outputs using the same keyword matching logic currently in PASTA's Stage 4 `build_prompt`. The keyword matching logic is extracted into a shared utility so all frameworks can use it.

### 7.2 Detection Keywords

| Condition | Keywords (case-insensitive match in prior outputs) |
|-----------|---------------------------------------------------|
| `api_detected` | REST, GraphQL, gRPC, API gateway, endpoint, OpenAPI, Swagger |
| `llm_detected` | LangChain, OpenAI, LLM, vector database, embedding, model serving, prompt, agent framework, Claude, GPT |
| `always` | No condition check; always injected |

---

## 8. Open Questions

| Question | Context |
|----------|---------|
| LINDDUN Pro reference depth | The LINDDUN threat tree catalogue is more extensive than OWASP's Top 10 list. How much of it should be inlined as prompt context vs. left to the agent's training knowledge? Start with concise category-level references (similar to OWASP approach) and expand if agent output quality is insufficient. |
| MITRE ATLAS version | ATLAS is updated periodically. The initial reference should target the most recent stable version at implementation time. Document the version in the constant module. |
| MAESTRO methodology maturity | MAESTRO is newer and less standardized than PASTA or STRIDE. The stage structure proposed here is derived from the methodology's published guidance but may need adjustment based on agent output quality during testing. Keep stage boundaries flexible during implementation. |
| Framework-specific scanner snippets | Should scanner snippets vary by framework? For example, Semgrep instructions for LINDDUN could emphasize data flow patterns rather than general security patterns. Start with generic snippets across all frameworks; add framework-specific variants if output quality warrants it. |
| Default framework communication | Changing the default from PASTA to 4QF+STRIDE is a user-facing change. Document clearly in changelog and README. Consider a one-time notice when users with `framework: pasta` in config run the tool after upgrade. |
| Cross-framework comparison | Should ThreatSmith support running two frameworks against the same codebase and diffing the results? Interesting for completeness validation but adds significant complexity. Defer. |

---

## 9. User Stories

### US-F01: Framework pack data model

**Description:** As a developer, I want a framework pack data model that defines the structure of a threat modeling methodology so that the orchestrator can run any framework without methodology-specific code.

**Acceptance Criteria:**

- `src/threatsmith/frameworks/__init__.py` exports `FrameworkPack`, `StageSpec`, and `get_framework(name)` function
- `StageSpec` dataclass has fields: `number`, `name`, `output_file`, `build_prompt` (callable)
- `FrameworkPack` dataclass has fields: `name`, `display_name`, `description`, `stages` (list of StageSpec), `report_stage` (StageSpec), `scanner_stages` (list of int), `reference_sets` (dict mapping stage number to reference config)
- `get_framework` returns the correct pack for `stride-4q`, `pasta`, `linddun`, `maestro`
- `get_framework` raises `ValueError` for unknown framework names with a message listing available frameworks
- Tests cover: data model construction, get_framework for all valid names, get_framework for invalid name

### US-F02: Framework registry and discovery

**Description:** As a developer, I want a framework registry so that available frameworks are discoverable at runtime for CLI help and validation.

**Acceptance Criteria:**

- `src/threatsmith/frameworks/__init__.py` exports `list_frameworks() -> list[FrameworkPack]` function
- Returns all registered framework packs
- Each pack in the list has a valid `name`, `display_name`, and `description`
- Framework registration requires no code changes to the registry module itself — each framework's `__init__.py` registers via the pack builder pattern
- Tests cover: list_frameworks returns all four frameworks, each has required fields

### US-F03: Prompt directory restructuring

**Description:** As a developer, I want prompt templates organized by framework in subdirectories so that each framework's prompts are isolated and independently maintainable.

**Acceptance Criteria:**

- `src/threatsmith/prompts/references/` contains shared reference modules: `owasp.py`, `scanner_snippets.py`, `stride_categories.py`, `linddun_catalogue.py`, `mitre_atlas.py`
- `src/threatsmith/prompts/stride_4q/` contains 4QF+STRIDE stage prompt modules
- `src/threatsmith/prompts/pasta/` contains PASTA stage prompt modules (migrated from current flat structure)
- `src/threatsmith/prompts/linddun/` contains LINDDUN Pro stage prompt modules
- `src/threatsmith/prompts/maestro/` contains MAESTRO stage prompt modules
- All existing PASTA imports continue to work (updated to new paths)
- All existing PASTA tests pass after migration

### US-F04: PASTA migration into pack structure

**Description:** As a developer, I want the existing PASTA prompts migrated into the framework pack structure with zero behavioral changes so that PASTA continues to work identically.

**Acceptance Criteria:**

- All PASTA prompt modules are moved to `src/threatsmith/prompts/pasta/`
- `src/threatsmith/prompts/pasta/__init__.py` exports a `build_pasta_pack() -> FrameworkPack` function
- The returned pack defines 7 analysis stages + 1 report stage with correct output filenames
- `scanner_stages` is `[5]`
- `reference_sets` includes OWASP Web Top 10 always on stage 4, with conditional API and LLM
- All existing PASTA tests pass without modification to test assertions (only import paths change if necessary)
- Running `threatsmith /path --framework pasta` produces identical behavior to the pre-refactor version

### US-F05: Orchestrator refactor for framework-agnostic execution

**Description:** As a developer, I want the orchestrator to iterate over a framework pack's stage list instead of hardcoded stage numbers so that it can run any framework.

**Acceptance Criteria:**

- `Orchestrator.__init__` accepts a `framework: FrameworkPack` parameter (replaces any hardcoded stage assumptions)
- `Orchestrator.run()` iterates `framework.stages` then runs `framework.report_stage`
- Output validation checks for `stage.output_file` instead of hardcoded filenames
- Context accumulation uses `stage.output_file` as the key for reading deliverables
- The orchestrator does not import or reference any framework-specific modules
- Tests cover: orchestrator with a mock 3-stage pack, orchestrator with PASTA pack (regression), output validation with framework-defined filenames

### US-F06: Assembler refactor for framework-agnostic prompt assembly

**Description:** As a developer, I want the assembler to use the framework pack's stage definitions and reference configuration instead of hardcoded stage-to-module mappings.

**Acceptance Criteria:**

- `assemble_prompt` accepts a `StageSpec` (or stage + pack) instead of a stage number
- `assemble_prompt` calls `stage.build_prompt(context)` directly instead of selecting a module by number
- Scanner snippets are injected only when the stage number is in `pack.scanner_stages`
- Reference sets are resolved from `pack.reference_sets[stage.number]` with conditional evaluation
- All existing assembler tests are updated to use the new interface
- Tests cover: assembly with scanner-eligible stage, assembly with non-scanner stage, assembly with conditional references

### US-F07: Conditional reference injection utility

**Description:** As a developer, I want a reusable utility for conditional reference injection so that all frameworks can use keyword-based detection for OWASP and other reference sets.

**Acceptance Criteria:**

- `src/threatsmith/prompts/references/__init__.py` (or a dedicated module) exports a `evaluate_reference_conditions(reference_config: list[dict], prior_outputs: dict) -> list[str]` function
- Evaluates each reference entry's condition against prior stage output text
- `always` condition returns the reference unconditionally
- `api_detected` condition matches against API-related keywords (case-insensitive)
- `llm_detected` condition matches against LLM-related keywords (case-insensitive)
- Returns a list of reference constant values to inject
- Keyword lists are configurable constants (not hardcoded in the function)
- Tests cover: always condition, api_detected with matching/non-matching text, llm_detected with matching/non-matching text, multiple conditions

### US-F08: STRIDE category reference constants

**Description:** As a developer, I want STRIDE category definitions as a constant so that the 4QF+STRIDE framework can inject them as a systematic reference.

**Acceptance Criteria:**

- `src/threatsmith/prompts/references/stride_categories.py` exports `STRIDE_CATEGORIES` constant
- Contains all six STRIDE categories with one-line descriptions
- Formatted as a concise reference block suitable for prompt injection
- Tests verify all six categories are present by initial letter (S, T, R, I, D, E)

### US-F09: LINDDUN threat catalogue reference constants *(deferred to future release)*

**Description:** As a developer, I want LINDDUN threat type definitions as a constant so that the LINDDUN Pro framework can inject them as a systematic reference.

**Acceptance Criteria:**

- `src/threatsmith/prompts/references/linddun_catalogue.py` exports `LINDDUN_THREAT_TYPES` constant with all seven categories: Linking, Identifying, Non-repudiation, Detecting, Data Disclosure, Unawareness, Non-compliance
- Each category includes the privacy property it protects
- Module exports `LINDDUN_DFD_PATTERNS` constant mapping DFD element types (process, data store, data flow, external entity) to common threat patterns per LINDDUN category
- Tests verify all seven categories are present and DFD patterns cover all four element types

### US-F10: MITRE ATLAS reference constants *(deferred to future release)*

**Description:** As a developer, I want MITRE ATLAS technique references as a constant so that the MAESTRO framework can inject them as a systematic reference.

**Acceptance Criteria:**

- `src/threatsmith/prompts/references/mitre_atlas.py` exports `MITRE_ATLAS_TECHNIQUES` constant
- Contains ATLAS tactics with high-relevance techniques, each with ID and one-line description
- Covers at minimum: reconnaissance, resource development, initial access, ML attack staging, ML model access, exfiltration, impact
- Formatted as a concise reference block suitable for prompt injection
- Tests verify all tactic categories are present

### US-F11: 4QF+STRIDE Stage 1 prompt — System Model

**Description:** As a developer, I want a prompt template for the 4QF+STRIDE System Model stage so that the agent produces a comprehensive application model as the foundation for threat identification.

**Acceptance Criteria:**

- `src/threatsmith/prompts/stride_4q/stage_01_system_model.py` exports `STAGE_PROMPT` constant
- Prompt covers: application purpose and scope, technology stack, data flows, actors and assets, trust boundaries, entry points, external dependencies, deployment context
- Prompt instructs the agent to produce at minimum one Mermaid DFD
- Prompt instructs the agent to write output to `threatmodel/01-system-model.md`
- Module exports `build_prompt(context: dict)` that injects user objectives when provided
- Tests cover: build_prompt with and without objectives

### US-F12: 4QF+STRIDE Stage 2 prompt — Threat Identification

**Description:** As a developer, I want a prompt template for the 4QF+STRIDE Threat Identification stage so that the agent performs systematic STRIDE analysis per component.

**Acceptance Criteria:**

- `src/threatsmith/prompts/stride_4q/stage_02_threat_identification.py` exports `STAGE_PROMPT` constant
- Prompt instructs systematic STRIDE analysis across all components identified in Stage 1
- Prompt requires threat scenarios for each applicable STRIDE category with attacker context
- Prompt references OWASP Top 10 as a coverage checklist
- Prompt instructs the agent to integrate scanner results when scanner context is present
- Prompt instructs the agent to write output to `threatmodel/02-threat-identification.md`
- Module exports `build_prompt(context: dict)` that injects Stage 1 output, STRIDE categories, OWASP references, and scanner context
- Tests cover: build_prompt with all context types, STRIDE reference injection, OWASP conditional injection, scanner snippet injection

### US-F13: 4QF+STRIDE Stage 3 prompt — Mitigations

**Description:** As a developer, I want a prompt template for the 4QF+STRIDE Mitigations stage so that the agent maps countermeasures to identified threats.

**Acceptance Criteria:**

- `src/threatsmith/prompts/stride_4q/stage_03_mitigations.py` exports `STAGE_PROMPT` constant
- Prompt covers: countermeasure identification per threat, existing controls assessment, gap analysis, implementation recommendations with effort, residual risk
- Prompt instructs the agent to write output to `threatmodel/03-mitigations.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-2 outputs
- Tests cover: build_prompt with prior stage context

### US-F14: 4QF+STRIDE Stage 4 prompt — Validation

**Description:** As a developer, I want a prompt template for the 4QF+STRIDE Validation stage so that the agent verifies completeness and identifies remaining gaps.

**Acceptance Criteria:**

- `src/threatsmith/prompts/stride_4q/stage_04_validation.py` exports `STAGE_PROMPT` constant
- Prompt covers: component coverage verification, STRIDE category coverage verification, mitigation completeness, remaining gaps, accepted risks, recommended next steps
- Prompt instructs the agent to write output to `threatmodel/04-validation.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-3 outputs
- Tests cover: build_prompt with prior stage context

### US-F15: 4QF+STRIDE Stage 5 prompt — Report Consolidation

**Description:** As a developer, I want a prompt template for the 4QF+STRIDE report consolidation step.

**Acceptance Criteria:**

- `src/threatsmith/prompts/stride_4q/stage_05_report.py` exports `STAGE_PROMPT` constant
- Prompt instructs consolidation of Stages 1-4 into a single executive report
- Prompt instructs preservation of Mermaid diagrams, threat tables, and mitigation recommendations
- Prompt instructs the agent to write output to `threatmodel/05-report.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-4 outputs
- Tests cover: build_prompt with all stage outputs

### US-F16: 4QF+STRIDE pack builder

**Description:** As a developer, I want a pack builder function that assembles the 4QF+STRIDE framework pack so that it can be registered in the framework registry.

**Acceptance Criteria:**

- `src/threatsmith/prompts/stride_4q/__init__.py` exports `build_stride_4q_pack() -> FrameworkPack`
- Pack has `name="stride-4q"`, `display_name="4QF + STRIDE"`
- Pack defines 4 analysis stages and 1 report stage with correct output filenames and build_prompt references
- `scanner_stages` is `[2]`
- `reference_sets` includes STRIDE categories (always) and OWASP Web Top 10 (always) on stage 2, with conditional API and LLM Top 10
- Tests verify pack structure, stage count, scanner stages, and reference configuration

### US-F17: LINDDUN Pro Stage 1 prompt — System Context and Data Inventory *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the LINDDUN Pro System Context stage focused on personal data inventory and regulatory context.

**Acceptance Criteria:**

- `src/threatsmith/prompts/linddun/stage_01_system_context.py` exports `STAGE_PROMPT` constant
- Prompt covers: personal data inventory, data subjects, processing purposes, legal basis, retention policies, regulatory context, third-party data sharing
- Prompt instructs the agent to examine data models, schemas, config, privacy policies, and documentation for privacy-relevant signals
- Prompt instructs the agent to write output to `threatmodel/01-system-context.md`
- Module exports `build_prompt(context: dict)` that injects user objectives when provided
- Tests cover: build_prompt with and without objectives

### US-F18: LINDDUN Pro Stage 2 prompt — Data Flow Decomposition *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the LINDDUN Pro Data Flow stage with privacy-annotated DFDs.

**Acceptance Criteria:**

- `src/threatsmith/prompts/linddun/stage_02_data_flow.py` exports `STAGE_PROMPT` constant
- Prompt instructs privacy-annotated Mermaid DFDs showing personal data flows with: data types, data subjects, processing purpose, encryption status, retention
- Prompt covers: trust boundaries with privacy significance, data minimization assessment, storage locations and access patterns
- Prompt instructs the agent to write output to `threatmodel/02-data-flow.md`
- Module exports `build_prompt(context: dict)` that injects Stage 1 output
- Tests cover: build_prompt with Stage 1 context

### US-F19: LINDDUN Pro Stage 3 prompt — Threat Elicitation *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the LINDDUN Pro Threat Elicitation stage with systematic per-DFD-element analysis across all seven LINDDUN categories.

**Acceptance Criteria:**

- `src/threatsmith/prompts/linddun/stage_03_threat_elicitation.py` exports `STAGE_PROMPT` constant
- Prompt instructs systematic application of all seven LINDDUN categories (L, I, N, D, D, U, N) to each DFD element from Stage 2
- Prompt requires concrete threat scenarios for each applicable category-element combination
- Prompt instructs cross-referencing with the LINDDUN threat catalogue
- Prompt instructs the agent to write output to `threatmodel/03-threat-elicitation.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-2 outputs and LINDDUN catalogue reference
- Tests cover: build_prompt with prior context and catalogue injection

### US-F20: LINDDUN Pro Stage 4 prompt — Threat Prioritization *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the LINDDUN Pro Threat Prioritization stage with privacy-focused risk assessment.

**Acceptance Criteria:**

- `src/threatsmith/prompts/linddun/stage_04_threat_prioritization.py` exports `STAGE_PROMPT` constant
- Prompt covers: likelihood and impact assessment with privacy-specific dimensions (data subjects affected, data sensitivity, regulatory consequences, reputational damage), risk rating, threat grouping, interacting threats
- Prompt instructs the agent to write output to `threatmodel/04-threat-prioritization.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-3 outputs
- Tests cover: build_prompt with prior stage context

### US-F21: LINDDUN Pro Stage 5 prompt — Mitigation Selection *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the LINDDUN Pro Mitigation stage with privacy enhancing technologies and privacy patterns.

**Acceptance Criteria:**

- `src/threatsmith/prompts/linddun/stage_05_mitigation.py` exports `STAGE_PROMPT` constant
- Prompt covers: PET mapping per threat, mitigation strategies organized by LINDDUN category, gap analysis, implementation recommendations, residual privacy risk, DPIA considerations
- Prompt references established privacy patterns (data minimization, anonymization, pseudonymization, etc.)
- Prompt instructs the agent to write output to `threatmodel/05-mitigation.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-4 outputs and LINDDUN mitigation references
- Tests cover: build_prompt with prior context and mitigation reference injection

### US-F22: LINDDUN Pro Stage 6 prompt — Report Consolidation *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the LINDDUN Pro report consolidation step.

**Acceptance Criteria:**

- `src/threatsmith/prompts/linddun/stage_06_report.py` exports `STAGE_PROMPT` constant
- Prompt instructs consolidation of Stages 1-5 into a single privacy risk report
- Prompt instructs preservation of DFDs, threat tables, and PET recommendations
- Prompt instructs the agent to write output to `threatmodel/06-report.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-5 outputs
- Tests cover: build_prompt with all stage outputs

### US-F23: LINDDUN Pro pack builder *(deferred to future release)*

**Description:** As a developer, I want a pack builder function that assembles the LINDDUN Pro framework pack.

**Acceptance Criteria:**

- `src/threatsmith/prompts/linddun/__init__.py` exports `build_linddun_pack() -> FrameworkPack`
- Pack has `name="linddun"`, `display_name="LINDDUN Pro"`
- Pack defines 5 analysis stages and 1 report stage with correct output filenames
- `scanner_stages` is `[]` (empty)
- `reference_sets` includes LINDDUN catalogue on stage 3 and mitigation references on stage 5
- Tests verify pack structure

### US-F24: MAESTRO Stage 1 prompt — AI System Profiling *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the MAESTRO AI System Profiling stage focused on inventorying AI/ML components, models, and agent capabilities.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/stage_01_ai_system_profiling.py` exports `STAGE_PROMPT` constant
- Prompt covers: AI/ML component inventory, model metadata, agent capabilities, integration points, training data sensitivity, business context
- Prompt instructs the agent to examine model configs, agent definitions, ML framework imports, API integrations, and pipeline definitions
- Prompt instructs the agent to write output to `threatmodel/01-ai-system-profiling.md`
- Module exports `build_prompt(context: dict)` that injects user objectives when provided
- Tests cover: build_prompt with and without objectives

### US-F25: MAESTRO Stage 2 prompt — Architecture and Data Flow *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the MAESTRO Architecture stage focused on AI-specific architecture decomposition and data flow.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/stage_02_architecture.py` exports `STAGE_PROMPT` constant
- Prompt covers: AI-specific architecture (model serving, training pipeline, feature stores, orchestration layers), training/inference/agent data flow diagrams (Mermaid), AI-specific trust boundaries, supply chain mapping
- Prompt instructs the agent to write output to `threatmodel/02-architecture.md`
- Module exports `build_prompt(context: dict)` that injects Stage 1 output
- Tests cover: build_prompt with Stage 1 context

### US-F26: MAESTRO Stage 3 prompt — Threat Identification *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the MAESTRO Threat Identification stage using MITRE ATLAS and OWASP LLM Top 10.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/stage_03_threat_identification.py` exports `STAGE_PROMPT` constant
- Prompt covers: systematic MITRE ATLAS technique analysis, prompt injection, data poisoning, model extraction, adversarial inputs, agent manipulation, supply chain attacks, information leakage
- Prompt references OWASP LLM Top 10 for coverage validation
- Prompt instructs the agent to write output to `threatmodel/03-threat-identification.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-2 outputs, MITRE ATLAS reference, and OWASP LLM Top 10
- Tests cover: build_prompt with prior context and reference injection

### US-F27: MAESTRO Stage 4 prompt — Vulnerability Analysis *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the MAESTRO Vulnerability Analysis stage focused on AI-specific vulnerabilities with scanner integration.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/stage_04_vulnerability_analysis.py` exports `STAGE_PROMPT` constant
- Prompt covers: input validation, output filtering, agent guardrails, training pipeline security, model access controls, ML framework dependency analysis, scanner results integration
- Prompt instructs the agent to write output to `threatmodel/04-vulnerability-analysis.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-3 outputs and scanner context
- Tests cover: build_prompt with and without scanner context

### US-F28: MAESTRO Stage 5 prompt — Attack Modeling *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the MAESTRO Attack Modeling stage with AI-specific attack trees and MITRE ATLAS mapping.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/stage_05_attack_modeling.py` exports `STAGE_PROMPT` constant
- Prompt covers: attack trees (Mermaid) for high-priority AI threats, multi-stage attack paths chaining AI and traditional vulnerabilities, MITRE ATLAS technique mapping, feasibility and impact assessment
- Prompt instructs the agent to write output to `threatmodel/05-attack-modeling.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-4 outputs and MITRE ATLAS reference
- Tests cover: build_prompt with prior context and ATLAS injection

### US-F29: MAESTRO Stage 6 prompt — Risk and Mitigation *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the MAESTRO Risk and Mitigation stage with AI-specific countermeasures and remediation roadmap.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/stage_06_risk_mitigation.py` exports `STAGE_PROMPT` constant
- Prompt covers: risk qualification, AI-specific countermeasures (guardrails, prompt hardening, model access controls, agent sandboxing, output filtering, model monitoring), traditional countermeasures in AI context, P0-P3 remediation roadmap, residual risk
- Prompt instructs the agent to write output to `threatmodel/06-risk-mitigation.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-5 outputs
- Tests cover: build_prompt with prior stage context

### US-F30: MAESTRO Stage 7 prompt — Report Consolidation *(deferred to future release)*

**Description:** As a developer, I want a prompt template for the MAESTRO report consolidation step.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/stage_07_report.py` exports `STAGE_PROMPT` constant
- Prompt instructs consolidation of Stages 1-6 into a single AI security risk report
- Prompt instructs preservation of architecture diagrams, attack trees, MITRE ATLAS mappings, and remediation roadmap
- Prompt instructs the agent to write output to `threatmodel/07-report.md`
- Module exports `build_prompt(context: dict)` that injects Stages 1-6 outputs
- Tests cover: build_prompt with all stage outputs

### US-F31: MAESTRO pack builder *(deferred to future release)*

**Description:** As a developer, I want a pack builder function that assembles the MAESTRO framework pack.

**Acceptance Criteria:**

- `src/threatsmith/prompts/maestro/__init__.py` exports `build_maestro_pack() -> FrameworkPack`
- Pack has `name="maestro"`, `display_name="MAESTRO"`
- Pack defines 6 analysis stages and 1 report stage with correct output filenames
- `scanner_stages` is `[4]`
- `reference_sets` includes MITRE ATLAS and OWASP LLM Top 10 on stage 3, and MITRE ATLAS on stage 5
- Tests verify pack structure

### US-F32: CLI --framework flag and --list-frameworks

**Description:** As a user, I want a `--framework` flag to select the threat modeling methodology and a `--list-frameworks` command to see available options.

**Acceptance Criteria:**

- `main.py` adds `--framework` option with default `stride-4q` and choices from the framework registry
- `main.py` adds `--list-frameworks` flag that prints available frameworks with descriptions and exits
- Selected framework is passed to the orchestrator
- `--framework` value is recorded in `metadata.json`
- `--rerun-stage` validates stage numbers against the selected framework's stage count
- Config file `framework` field is respected with CLI override
- Tests cover: default framework, explicit framework selection, list-frameworks output, invalid framework name, stage number validation per framework

### US-F33: Metadata framework tracking

**Description:** As a user, I want `metadata.json` to record which framework was used so that re-runs, updates, and tooling can identify the methodology.

**Acceptance Criteria:**

- `generate_metadata` accepts a `framework: FrameworkPack` parameter
- `metadata.json` includes `framework` (pack name) and `framework_display_name` fields
- `metadata.json` includes `stages_completed` count
- When resuming or re-running, the wrapper warns if the current `--framework` differs from the framework recorded in existing metadata
- Tests cover: metadata with framework fields, framework mismatch warning

### US-F34: End-to-end test for 4QF+STRIDE pipeline

**Description:** As a developer, I want an end-to-end test verifying the full 4QF+STRIDE pipeline from CLI invocation to deliverable output.

**Acceptance Criteria:**

- `tests/test_e2e_stride_4q.py` tests the full pipeline with `--framework stride-4q` using a mock engine
- Test verifies all 5 deliverable files (01-04 + 05-report) are created
- Test verifies Stage 2 prompt contains STRIDE categories reference
- Test verifies metadata includes `framework: "stride-4q"`
- Test verifies context accumulation across 4 analysis stages
- Tests pass

### US-F35: End-to-end test for LINDDUN Pro pipeline *(deferred to future release)*

**Description:** As a developer, I want an end-to-end test verifying the full LINDDUN Pro pipeline.

**Acceptance Criteria:**

- `tests/test_e2e_linddun.py` tests the full pipeline with `--framework linddun` using a mock engine
- Test verifies all 6 deliverable files (01-05 + 06-report) are created
- Test verifies Stage 3 prompt contains LINDDUN catalogue reference
- Test verifies no scanner context is injected (scanner_stages is empty)
- Test verifies metadata includes `framework: "linddun"`
- Tests pass

### US-F36: End-to-end test for MAESTRO pipeline *(deferred to future release)*

**Description:** As a developer, I want an end-to-end test verifying the full MAESTRO pipeline.

**Acceptance Criteria:**

- `tests/test_e2e_maestro.py` tests the full pipeline with `--framework maestro` using a mock engine
- Test verifies all 7 deliverable files (01-06 + 07-report) are created
- Test verifies Stage 3 prompt contains MITRE ATLAS and OWASP LLM Top 10 references
- Test verifies Stage 4 prompt contains scanner context (when scanners available)
- Test verifies metadata includes `framework: "maestro"`
- Tests pass

### US-F37: PASTA regression test after migration

**Description:** As a developer, I want a regression test confirming that PASTA behaves identically after migration into the pack structure.

**Acceptance Criteria:**

- `tests/test_e2e_pasta_regression.py` runs the full PASTA pipeline with `--framework pasta` using a mock engine
- Test verifies all 8 deliverable files are created with original filenames
- Test verifies Stage 4 prompt contains OWASP references (same conditional logic)
- Test verifies Stage 5 prompt contains scanner snippets (same injection logic)
- Test verifies metadata includes `framework: "pasta"`
- Test assertions match the existing `test_e2e.py` assertions (adapted for the `--framework` flag)
- Tests pass
