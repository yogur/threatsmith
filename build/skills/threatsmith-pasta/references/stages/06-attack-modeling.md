# Stage 6 — Attack Modeling

This stage transforms the Stage 4 threats and Stage 5 vulnerabilities into concrete, realistic attack scenarios with detailed exploitation paths — bridging "what could go wrong" and "how an attacker would actually do it." The attack intelligence it produces drives risk prioritization and remediation planning in Stage 7.

**Model ALL significant threats** from the Stage 4 inventory, and ensure **every confirmed Stage 5 vulnerability** appears in at least one attack scenario. Partial coverage is not acceptable.

**Deliverable:** write your analysis to `06-attack-modeling.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-objectives.md` through `05-vulnerability-analysis.md` from the output directory. Use Stage 1 objectives and data classifications to determine what attackers target and what impact matters; Stage 2 scope for relevant attack techniques and MITRE mappings; Stage 3 decomposition for the attack surface (entry points, trust boundaries, data flows); the Stage 4 threat inventory as your coverage checklist; and the Stage 5 vulnerabilities (with CVSS, CWE, and code locations) as the building blocks of your attack trees.

## Mode framing

- **from-code** — Build attack trees grounded in the confirmed Stage 5 vulnerabilities and validate each exploitation step against the actual code, referencing specific files and lines.
- **from-docs** — Without code, model the attack paths the *design* permits: how an attacker would chain the design's weak points and trust-boundary gaps. Frame trees around designed entry points and controls, and note that exploit steps are projected rather than validated against an implementation.
- **pair** — Develop the most important attack trees with the human, confirming which controls exist and where bypasses are plausible.

## Analysis pillars

Address each of these four pillars (they become the top-level sections of your output):

### 1. Attack surface analysis

For every component with confirmed vulnerabilities or significant threats: an **entry-point inventory** (cross-referencing Stage 3 entry points and Stage 5 vulnerabilities — network endpoints, file/data ingestion, inter-component channels, admin interfaces, implicit entry points); an **exposure assessment** per entry point (accessible to which trust level? what input, validated how? what trust assumptions? what blast radius?); the **pre-remediation attack surface** (today's surface with all Stage 5 vulnerabilities present — the baseline for attack trees); the **post-remediation attack surface** (how it changes if Stage 5 remediations are implemented — which paths are eliminated, which residual surface remains; this feeds Stage 7's cost-benefit analysis); and **attack-surface reduction opportunities** (structural reductions beyond specific fixes — removing unnecessary endpoints, restricting permissive interfaces, isolating components behind new trust boundaries).

### 2. Attack tree development

Build detailed attack trees for every significant threat using Mermaid `flowchart TD` diagrams — these are the core deliverable of this stage. Each tree follows a goal-decomposition pattern: a **root node** (attacker objective, e.g. "Exfiltrate customer PII", "Gain administrative access"), **sub-goal nodes**, **technique nodes**, **prerequisite nodes**, and **control nodes** (existing controls the attacker must bypass). Use **AND/OR decomposition** — OR nodes for alternative techniques, AND nodes where all children are required.

Mermaid requirements: `flowchart TD` for hierarchy; descriptive node labels (`A[Goal: Exfiltrate Customer Data]`, not `A[Attack]`); diamond shapes `{Decision}` for OR points; annotate edges with prerequisites where relevant; **avoid parentheses inside node labels** — use hyphens or commas (`A[Auth Module - JWT, OIDC]`); keep one tree per major objective rather than one monolithic diagram; each diagram self-contained and readable.

**MITRE ATT&CK integration:** map each attack technique to the relevant tactic/technique where applicable (e.g. T1190 "Exploit Public-Facing Application"). Relevant tactics for application-level attacks include Initial Access (TA0001), Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004), Defense Evasion (TA0005), Credential Access (TA0006), Discovery (TA0007), Lateral Movement (TA0008), Collection (TA0009), Exfiltration (TA0010), and Impact (TA0040) — but this is not exhaustive; use any applicable technique. Not every application-specific attack has a direct MITRE mapping, and that's expected — connect where it adds analytical value, don't force it.

### 3. Attack-vulnerability-exploit analysis

For each attack path, trace the complete chain from technique to specific vulnerability to concrete exploit, grounded in the Stage 5 evidence: the **attack technique** described concretely (not "SQL injection" generically, but "second-order SQL injection via the username field stored in sessions and later interpolated into an admin query"); **vulnerability linkage** (the specific Stage 5 finding by identifier, CWE, CVSS, and code location); an **exploit scenario** (step-by-step — initiating input, how it traverses the app, where the vulnerability triggers, what the attacker gains, how it enables the next step); **prerequisite analysis** (access level, system state, timing, knowledge, tooling); **existing control analysis** (does each control block the attack or can it be bypassed? include bypasses as tree steps); and **vulnerability chaining** (chain entry point, intermediate steps, terminus, and the amplification effect where chained impact exceeds any individual vulnerability).

### 4. Impact summary and risk narrative

For each major scenario: an **attack narrative** in plain language understandable by a non-specialist technical manager; a **technical impact assessment** (Confidentiality — what data is exposed, referencing Stage 1 classification; Integrity — what can be modified; Availability — temporary vs. permanent disruption); a **business impact assessment** (affected stakeholders, regulatory exposure, operational disruption and recovery effort, reputational risk); an **attack feasibility assessment** (skill level — Script kiddie/Intermediate/Advanced/Expert; tooling; time to exploit; detection likelihood and monitoring gaps); and an **aggregate risk summary** for trees with multiple paths (lowest-barrier path, highest-impact path, most-likely-to-succeed path, and residual risk after Stage 5 remediations).

## Investigation approach

- **Context integration and attack-surface mapping** — review prior outputs; map the attack surface (Pillar 1); build a tracking list of every Stage 4 threat and Stage 5 vulnerability that must appear.
- **Attack-tree construction and exploit analysis** — build trees with Mermaid (Pillar 2), map to MITRE, trace Attack→Vulnerability→Exploit (Pillar 3), validate feasibility against the code, identify chains.
- **Impact synthesis and completeness validation** — write impact narratives (Pillar 4); compare pre- and post-remediation attack surfaces; verify every Stage 4 threat is in a tree and every Stage 5 vulnerability is in an exploit analysis.

## Output

Write `06-attack-modeling.md` with the four pillar headings as top-level sections (## Attack Surface Analysis, ## Attack Tree Development, ## Attack-Vulnerability-Exploit Analysis, ## Impact Summary and Risk Narrative). For each attack tree include a Mermaid flowchart, MITRE technique IDs on applicable nodes, a textual description of each path, and prerequisites/controls per path. For each exploit chain include the specific Stage 5 vulnerability (identifier and code location), a step-by-step sequence grounded in the codebase, prerequisite and control analysis, and chaining analysis. For each impact summary include the plain-language narrative, CIA assessment with data-classification references, business impact, and feasibility.

**Completeness requirements:**

- Every significant Stage 4 threat is modeled in at least one attack tree.
- Every confirmed Stage 5 vulnerability appears in at least one exploit analysis.
- Attack-surface analysis covers all components with confirmed vulnerabilities; impact summaries cover all major scenarios; pre- vs. post-remediation comparison is present.

**Quality standards:**

- Ground all models in evidence — specific files, functions, line numbers (or design references in `from-docs` mode).
- Attack trees must be realistic and technically feasible, not theoretical; Mermaid must be syntactically valid.
- Be specific: *"Attacker exploits CWE-89 SQL injection in api/users.py:34 via crafted user_id to extract the users table, then uses recovered password hashes to authenticate as admin via T1078 Valid Accounts"* beats *"attacker could use SQL injection to gain access."*

Your attack models bridge vulnerability findings and risk prioritization: Stage 7 uses your trees for risk severity, your feasibility assessments for likelihood, and your impact narratives for business consequences.
