# Stage 3 — Mitigations

**Four Question Framework question:** *What are we going to do about it?*

This stage maps countermeasures to every threat from Stage 2, assesses controls that already exist, identifies gaps, and gives actionable, prioritized implementation recommendations.

**Deliverable:** write your analysis to `03-mitigations.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-system-model.md` and `02-threat-identification.md` from the output directory. Build a complete inventory of the threats requiring mitigation — **every threat from Stage 2 must appear in your analysis; none may be silently dropped.**

## Mode framing

- **from-code** — Assess the controls actually present in the codebase, judge their effectiveness, and reference exact files/functions/configs for both existing controls and recommended changes.
- **from-docs** — The implementation may not exist yet, so frame mitigations as **design requirements and recommended controls** the build should include, rather than fixes to existing code. Note which controls the design already commits to versus which are gaps to be designed in.
- **pair** — Propose countermeasures and discuss feasibility/effort with the human, capturing decisions (accept, mitigate, defer) as you go.

## Conditional reference guidance

When proposing countermeasures for threats tied to a specific surface, consult the matching OWASP reference (synced into `references/`) for established mitigation guidance: `references/owasp-api-top-10.md` for API threats, `references/owasp-llm-top-10.md` for LLM/AI threats, `references/owasp-mobile-top-10.md` for mobile threats. Use the same conditional logic Stage 2 used — pull in the references that match the system's nature.

## Analysis approach

### Countermeasures per threat

For every Stage 2 threat, identify one or more countermeasures and map each to the STRIDE category and component(s) it addresses (one countermeasure may cover several threats):

- **Preventive** — eliminate or reduce likelihood (input validation, parameterized queries, strong auth, encryption in transit and at rest).
- **Detective** — detect exploitation in progress or after the fact (IDS, anomaly monitoring, audit logging, integrity checks).
- **Corrective** — limit damage and restore operation (incident response, automated rollback, backup/recovery, circuit breakers).

### Existing controls assessment

Identify controls already in place — authentication/authorization, input validation and sanitization, encryption and data protection, logging and monitoring, error handling, rate limiting/abuse prevention, dependency management. For each, assess whether it's correctly implemented, covers all relevant entry points and data flows, has bypasses or weaknesses, and meets best practice. (In `from-docs` mode, assess which controls the design commits to.)

### Gap analysis

Compare threats against controls and classify each threat as **covered** (adequate control — document it), **partially covered** (control exists but incomplete/misconfigured — document what's missing), or **uncovered** (no countermeasure — needs a new control).

### Implementation recommendations

For each gap, provide:

- **Recommended countermeasure** — specific and actionable, with enough detail to implement; reference the files/functions/configs that change.
- **Effort estimate** — **Low** (config change, library upgrade, minor code change — hours to a day), **Medium** (new component, significant refactor, integration — days to a week), or **High** (architectural change, new infrastructure, cross-cutting change — weeks).
- **Priority** — based on the Stage 2 severity and the effort: **P0** (critical, immediate), **P1** (high, soon), **P2** (medium, next cycle), **P3** (low, backlog).
- **Implementation guidance** — concrete steps, patterns, libraries, or configurations, referencing where changes should be made.

### Residual risk

For each threat, document the risk that remains after the proposed mitigations: what residual risk persists, which threats can't be fully mitigated and must be accepted, what compensating controls exist for accepted risks, and any dependence on external parties (cloud providers, third-party services) for risk reduction.

## Output

Write `03-mitigations.md` with these sections:

1. **Executive Summary** — how many threats are covered / partially covered / uncovered, and an overall risk-reduction assessment.
2. **Existing Controls Inventory** — controls found, with effectiveness assessment.
3. **Gap Analysis** — organized by threat: current state, gaps, recommended countermeasures.
4. **Prioritized Recommendations** — all recommendations sorted P0 → P3 with effort estimates and implementation guidance.
5. **Residual Risk Summary** — remaining risks after all recommended mitigations, including accepted risks with justification.

**Quality standards:**

- Every Stage 2 threat appears in the analysis — no silent drops.
- Recommendations are specific and actionable — exact files, functions, configurations.
- Effort estimates are realistic — don't underestimate architectural change.
- Distinguish quick wins (low effort, high impact) from strategic improvements (high effort, high impact).
- Ground assessments in evidence (code in `from-code`, design in `from-docs`) — not generic security advice.

This mitigation plan is the actionable remediation roadmap; Stage 4 verifies its completeness and overall quality.
