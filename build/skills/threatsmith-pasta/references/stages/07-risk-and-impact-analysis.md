# Stage 7 — Risk and Impact Analysis

This is the decision-making stage. It qualifies and quantifies the business impact of every Stage 6 attack scenario, identifies countermeasures, assesses residual risk after mitigation, and produces a prioritized remediation roadmap — translating attack intelligence into actionable risk-management decisions grounded in business value.

**Every Stage 6 attack scenario receives a risk assessment**, and **every confirmed Stage 5 vulnerability has an associated countermeasure or an explicit acceptance rationale.** Partial coverage is not acceptable.

**Deliverable:** write your analysis to `07-risk-and-impact-analysis.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-objectives.md` through `06-attack-modeling.md` from the output directory. Use Stage 1 objectives and data classifications to ground impact in business terms; Stage 2 scope for countermeasure feasibility; Stage 3 data flows and trust boundaries for blast radius; Stage 4 for threat-landscape context; Stage 5 vulnerabilities as the foundation for countermeasures; and Stage 6 attack trees and feasibility assessments as the basis for risk qualification.

## Mode framing

- **from-code** — Ground countermeasures in specific code changes (file and line references) and base risk ratings on the confirmed, CVSS-scored findings.
- **from-docs** — Frame countermeasures as **design requirements and recommended controls** to build in, rather than fixes to existing code. Risk ratings rest on the designed/implied controls; note that likelihood and CVSS are provisional until implementation. The roadmap becomes "security requirements for the build" rather than a remediation backlog.
- **pair** — Develop risk ratings and countermeasures with the human, capturing which risks they accept, defer, or commit to mitigating, and who owns each decision.

## Analysis pillars

Address each of these five pillars (they become the top-level sections of your output):

### 1. Business impact qualification and quantification

For each Stage 6 attack scenario, move beyond technical severity (CVSS) to real-world consequences. **Impact qualification** on a structured scale: Critical (existential — regulatory shutdown, mass restricted-data breach, loss of core function), High (major disruption — significant financial loss, confidential-data breach, extended outage, enforcement action), Medium (moderate — limited exposure, partial degradation, internal compliance finding), Low (minor — non-sensitive exposure, brief disruption, cosmetic/reputational nuisance). **Impact quantification** where possible: data-exposure scope (records/users/assets, referencing Stage 1 classification and Stage 3 assets), financial exposure (order-of-magnitude — GDPR up to 4% of turnover, HIPAA up to $1.5M per violation category, breach-notification and legal costs, remediation labor, business interruption), operational-impact duration (minutes/hours/days/weeks to recover), and blast radius (downstream systems, users, processes — referencing Stage 3 flows and boundaries). **Likelihood assessment** combining Stage 6 feasibility and Stage 5 CVSS into a composite rating: Almost Certain / Likely / Possible / Unlikely / Rare. **Risk rating** combining impact and likelihood into a matrix rating (Critical/High/Medium/Low) that drives prioritization.

### 2. Countermeasure identification

For each vulnerability and attack path, identify specific, actionable countermeasures across categories: **preventive** (code-level fixes, architectural changes, configuration hardening, dependency updates), **detective** (logging/monitoring enhancements, IDS rules, anomaly detection, alert thresholds), **corrective** (incident-response procedures, backup/recovery, circuit breakers, notification plans), and **compensating** (WAF rules, rate limiting, enhanced monitoring, access restrictions as interim protection). For each countermeasure specify: what it addresses (vulnerability ID, CWE, attack-path reference), implementation approach (specific changes), effort estimate (hours/days/weeks, relative), and dependencies (does this fix require other changes first?).

### 3. Residual risk assessment

After countermeasures, assess what remains. For each scenario post-countermeasure: **residual vulnerability** (does the fix fully eliminate the weakness or only reduce exploitability?); **residual attack surface** (which Stage 6 paths are eliminated, degraded, or unchanged); **residual impact** (worst-case if the residual is exploited — reduced blast radius, data exposure, or window?); **residual likelihood** (reassessed skill, detection, and time-to-exploit); **residual risk rating** (recalculated matrix rating vs. the pre-countermeasure rating, to quantify reduction); and **risk-acceptance criteria** for residuals that can't be further reduced (why acceptable, who should formally accept it, and what conditions trigger re-evaluation).

### 4. Mitigation effectiveness vs. cost analysis

For each countermeasure (or group): **effectiveness** (risk-reduction magnitude — e.g. Critical→Medium; coverage breadth — how many paths it closes; durability — permanent vs. ongoing maintenance; defense-in-depth contribution); **cost** (implementation effort, operational cost, opportunity cost, and risk-of-introduction — could the fix break functionality or cause regressions?); a **cost-effectiveness ranking** (quick wins — high reduction/low cost, implement now; strategic investments — high reduction/high cost, plan and schedule; diminishing returns — low reduction/high cost, defer; maintenance items — low reduction/low cost, regular cycle); and **residual benefits** (cross-cutting gains — fixing a shared library or hardening a shared auth mechanism protects other consumers; adding monitoring for one path detects others; a new trust boundary reduces future attack surface). Document these cross-cutting benefits — they raise a countermeasure's effective value and should influence prioritization.

### 5. Prioritized remediation roadmap

Synthesize everything into a concrete, prioritized plan — the primary action-oriented deliverable of the whole threat model. Organize into tiers by risk rating, cost-effectiveness, and residual benefit: **P0 — Immediate** (critical/high risk with low-cost fixes, actively exploitable items, regulatory-compliance gaps, quick wins); **P1 — Short-term** (high-risk items of moderate effort, high-coverage countermeasures, items where residual benefits amplify value); **P2 — Medium-term** (medium-risk items needing architectural change, strategic investments, defense-in-depth improvements); **P3 — Long-term** (low-risk diminishing-returns items, aspirational hardening, items dependent on broader platform changes). For each item: vulnerability reference (Stage 5 ID, CWE, code location), countermeasure summary, risk reduction (from X to Y on the matrix), effort estimate, dependencies, residual benefits, and acceptance criteria.

## Investigation approach

- **Context integration and risk assessment** — review prior outputs; qualify and quantify impact for every scenario (Pillar 1); build a tracking list of every Stage 6 scenario and Stage 5 vulnerability needing countermeasures.
- **Countermeasure development and residual-risk analysis** — identify countermeasures (Pillar 2), assess residual risk (Pillar 3), analyze cost-effectiveness and residual benefits (Pillar 4); validate every Stage 5 vulnerability has a countermeasure or acceptance rationale.
- **Roadmap synthesis and completeness validation** — prioritize into P0–P3 (Pillar 5); verify every Stage 6 scenario has a risk assessment and every Stage 5 vulnerability has a countermeasure or rationale.

## Output

Write `07-risk-and-impact-analysis.md` with the five pillar headings as top-level sections (## Business Impact Qualification and Quantification, ## Countermeasure Identification, ## Residual Risk Assessment, ## Mitigation Effectiveness vs Cost Analysis, ## Prioritized Remediation Roadmap). Include per-scenario risk assessments (impact qualification + quantification, likelihood, matrix rating), per-countermeasure details (what it addresses, approach, effort, dependencies, category), per-residual-risk reassessments (post-countermeasure status, updated rating vs. original, acceptance criteria), the cost-effectiveness analysis (reduction magnitude, coverage, cost dimensions, ranking, residual benefits), and the roadmap (P0–P3 tiers with per-item details and dependency ordering).

**Completeness requirements:**

- Every Stage 6 attack scenario has a risk assessment; every confirmed Stage 5 vulnerability has a countermeasure or acceptance rationale.
- Residual risk is assessed for every countermeasure; cost-effectiveness covers all significant countermeasures; the roadmap includes all countermeasures by priority; residual benefits are documented for cross-cutting countermeasures.

**Quality standards:**

- Ground risk assessments in evidence from prior stages — reference specific attack trees, CVSS scores, data classifications, and business objectives.
- Countermeasures must be specific and actionable — "implement input validation" is insufficient; "add a parameterized query in api/users.py:34 replacing string interpolation for user_id" is actionable.
- The roadmap must be immediately usable — each item should convert directly into a work ticket.
- Be specific: *"Apply parameterized queries to resolve CWE-89 in api/users.py:34, reducing risk from Critical to Low. Effort: 2 hours. Residual benefit: also protects admin/reports.py:112, which uses the same query builder"* beats *"fix SQL injection vulnerabilities."*

Your risk and impact analysis is the culmination of the PASTA process — the roadmap you produce determines which security improvements get built and in what order.
