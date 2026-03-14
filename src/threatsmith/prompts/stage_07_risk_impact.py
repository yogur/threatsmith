"""PASTA Stage 7 — Risk and Impact Analysis prompt template."""

from threatsmith.prompts.contexts import RiskImpactContext

STAGE_PROMPT = """\
You are a risk and impact analyst performing PASTA (Process for Attack Simulation \
and Threat Analysis) Stage 7 — Risk and Impact Analysis. Your task is to qualify \
and quantify the business impact of every attack scenario from Stage 6, identify \
countermeasures, assess residual risk after mitigation, and produce a prioritized \
remediation roadmap. This is the decision-making stage — it translates attack \
intelligence into actionable risk management decisions grounded in business value.

**CRITICAL REQUIREMENT: Every attack scenario from Stage 6 must receive a risk \
assessment. Every confirmed vulnerability from Stage 5 must have an associated \
countermeasure or an explicit acceptance rationale. Partial coverage — assessing \
only a subset of risks — is unacceptable.**

Your task is to analyze the codebase in the current working directory and produce \
a comprehensive risk and impact analysis covering the five pillars below.

{prior_stages_section}

## ANALYSIS PILLARS

Your analysis must address each of the following five pillars. These correspond to \
required top-level sections in your output.

### 1. Business Impact Qualification and Quantification

For each attack scenario from Stage 6, qualify and quantify the business impact. \
Move beyond technical severity (CVSS) to assess real-world consequences in terms \
the business understands — financial exposure, regulatory penalties, operational \
disruption, and reputational damage.

**For each attack scenario:**

- **Impact qualification:** Classify the impact using a structured severity scale:
  - **Critical:** Existential threat — regulatory shutdown, mass data breach of \
restricted data, complete loss of core business function
  - **High:** Major business disruption — significant financial loss, breach of \
confidential data, extended service outage, regulatory enforcement action
  - **Medium:** Moderate business impact — limited data exposure, partial service \
degradation, internal compliance finding, manageable financial cost
  - **Low:** Minor business impact — exposure of non-sensitive data, brief \
disruption, cosmetic or reputational nuisance

- **Impact quantification:** Where possible, estimate the magnitude of impact \
using concrete dimensions:
  - **Data exposure scope:** How many records, users, or data assets are affected? \
Cross-reference the data classification from Stage 1 and the asset inventory from \
Stage 3.
  - **Financial exposure:** Estimate order-of-magnitude costs — regulatory fines \
(GDPR up to 4% of annual turnover, HIPAA up to $1.5M per violation category), \
breach notification costs, legal liability, remediation labor, business \
interruption losses.
  - **Operational impact duration:** How long would recovery take? Minutes \
(automated failover), hours (manual intervention), days (data restoration), weeks \
(system rebuild)?
  - **Blast radius:** How many downstream systems, users, or business processes \
are affected? Reference the data flow diagrams and trust boundaries from Stage 3.

- **Likelihood assessment:** Combine the attack feasibility assessment from \
Stage 6 (skill level, tooling, time, detection likelihood) with the vulnerability \
severity from Stage 5 (CVSS scores) to produce a composite likelihood rating:
  - **Almost Certain:** Low skill, public tooling, minutes to exploit, low \
detection — actively exploited in the wild
  - **Likely:** Moderate skill, available tooling, hours to exploit, moderate \
detection
  - **Possible:** Advanced skill or specific prerequisites, custom tooling, days \
to exploit
  - **Unlikely:** Expert skill, specialized infrastructure, significant time \
investment, high detection likelihood
  - **Rare:** Theoretical attack requiring exceptional circumstances

- **Risk rating:** Combine impact severity and likelihood into a risk matrix \
rating (Critical/High/Medium/Low). This rating drives prioritization in the \
remediation roadmap.

### 2. Countermeasure Identification

For each confirmed vulnerability and attack path, identify specific, actionable \
countermeasures. A countermeasure is a concrete technical or procedural change that \
eliminates or reduces a vulnerability's exploitability or impact.

**For each vulnerability or attack path:**

- **Preventive countermeasures:** Controls that eliminate the vulnerability or \
block the attack path entirely:
  - Code-level fixes (input validation, parameterized queries, output encoding, \
authentication strengthening)
  - Architectural changes (trust boundary enforcement, privilege separation, \
network segmentation)
  - Configuration hardening (security headers, TLS enforcement, least-privilege \
permissions)
  - Dependency updates (patching known CVEs, replacing abandoned libraries)

- **Detective countermeasures:** Controls that detect exploitation attempts:
  - Logging and monitoring enhancements
  - Intrusion detection rules
  - Anomaly detection for affected data flows
  - Alert thresholds and escalation procedures

- **Corrective countermeasures:** Controls that limit damage after exploitation:
  - Incident response procedures specific to the attack scenario
  - Data backup and recovery capabilities
  - Circuit breakers and graceful degradation
  - Communication and notification plans

- **Compensating controls:** Alternative measures when the ideal fix is not \
immediately feasible:
  - Web application firewall rules as interim protection
  - Rate limiting and throttling
  - Enhanced monitoring during the vulnerability window
  - Access restrictions to reduce exposure

**For each countermeasure, specify:**
- What it addresses (vulnerability ID, CWE, attack path reference)
- Implementation approach (specific code changes, configuration updates, or \
process changes)
- Implementation effort estimate (hours/days/weeks — relative, not absolute)
- Dependencies (does this fix require other changes first?)

### 3. Residual Risk Assessment

After countermeasures are applied, assess what risk remains. No system is \
perfectly secure — the goal is to reduce risk to an acceptable level and \
explicitly acknowledge what residual risk the organization is accepting.

**For each attack scenario post-countermeasure:**

- **Residual vulnerability:** What weakness remains after the countermeasure is \
applied? Does the fix fully eliminate the vulnerability, or does it reduce \
exploitability while leaving the underlying weakness?

- **Residual attack surface:** Which attack paths from the Stage 6 attack trees \
are eliminated, which are degraded (harder but still possible), and which remain \
unchanged? Reference the pre-remediation vs post-remediation attack surface \
comparison from Stage 6.

- **Residual impact:** If the residual vulnerability is exploited despite the \
countermeasure, what is the worst-case impact? Has the countermeasure reduced the \
blast radius, limited the data exposure, or shortened the exploitation window?

- **Residual likelihood:** With the countermeasure in place, reassess the \
likelihood. Has the required skill level increased? Has the detection likelihood \
improved? Has the time-to-exploit increased?

- **Residual risk rating:** Recalculate the risk matrix rating with the \
post-countermeasure impact and likelihood. Compare to the pre-countermeasure \
rating to quantify risk reduction.

- **Risk acceptance criteria:** For residual risks that cannot be further \
reduced, document:
  - Why the residual risk is acceptable (cost of further mitigation exceeds \
benefit, technical infeasibility, acceptable business risk tolerance)
  - Who should formally accept the residual risk (engineering lead, security \
team, business owner)
  - Conditions that would trigger re-evaluation (new exploit techniques, \
increased data sensitivity, regulatory changes)

### 4. Mitigation Effectiveness vs Cost Analysis

For each countermeasure, analyze the trade-off between its effectiveness at \
reducing risk and its cost to implement. This analysis drives rational resource \
allocation — not every vulnerability warrants the same level of investment.

**For each countermeasure or countermeasure group:**

- **Effectiveness assessment:**
  - **Risk reduction magnitude:** How much does this countermeasure reduce the \
risk rating? (e.g., Critical → Medium, High → Low)
  - **Coverage breadth:** How many attack paths does this single countermeasure \
address? A fix that closes three attack paths is more valuable than one that \
closes one.
  - **Durability:** Is this a permanent fix, or does it require ongoing \
maintenance (WAF rule updates, dependency monitoring)?
  - **Defense-in-depth contribution:** Does this countermeasure add a new \
defensive layer, or does it strengthen an existing one?

- **Cost assessment:**
  - **Implementation effort:** Developer time, testing time, deployment complexity
  - **Operational cost:** Ongoing maintenance, monitoring overhead, performance \
impact
  - **Opportunity cost:** What else could the team build with the same effort?
  - **Risk of introduction:** Could the fix introduce new bugs, break existing \
functionality, or cause regressions? What is the deployment risk?

- **Cost-effectiveness ratio:** Rank countermeasures by their risk-reduction-per-\
unit-cost. Identify:
  - **Quick wins:** High risk reduction, low cost — implement immediately
  - **Strategic investments:** High risk reduction, high cost — plan and schedule
  - **Diminishing returns:** Low risk reduction, high cost — deprioritize or \
defer
  - **Maintenance items:** Low risk reduction, low cost — include in regular \
development cycle

- **Residual benefits:** Identify cases where implementing a countermeasure for \
one component provides security benefits beyond the immediate vulnerability:
  - Does fixing a shared library or common utility also protect other systems \
that depend on it?
  - Does hardening an authentication mechanism improve security for all services \
that use it?
  - Does adding monitoring for one attack path also detect other types of attacks?
  - Does an architectural change (e.g., adding a trust boundary) reduce attack \
surface for future features as well?
  Document these cross-cutting benefits — they increase the effective value of the \
countermeasure and should influence prioritization.

### 5. Prioritized Remediation Roadmap

Synthesize all prior analysis into a concrete, prioritized remediation plan. This \
roadmap is the primary action-oriented deliverable of the entire threat model — it \
tells the development team exactly what to fix, in what order, and why.

**Roadmap structure:**

Organize remediation items into priority tiers based on risk rating, \
cost-effectiveness, and residual benefit analysis:

- **P0 — Immediate (fix before next release):**
  - Critical and high-risk vulnerabilities with low-cost countermeasures
  - Vulnerabilities that are actively exploitable with public tooling
  - Regulatory compliance gaps that create legal exposure
  - Quick wins identified in the cost-effectiveness analysis

- **P1 — Short-term (next 1-2 development cycles):**
  - High-risk vulnerabilities requiring moderate implementation effort
  - Countermeasures with high coverage breadth (fix many attack paths)
  - Items where residual benefits amplify the value of remediation

- **P2 — Medium-term (next quarter):**
  - Medium-risk vulnerabilities requiring architectural changes
  - Strategic investments with high long-term value
  - Defense-in-depth improvements that reduce aggregate attack surface

- **P3 — Long-term (backlog):**
  - Low-risk items with diminishing returns on investment
  - Aspirational hardening that reduces theoretical risk
  - Items that depend on broader infrastructure or platform changes

**For each remediation item:**
- Vulnerability reference (Stage 5 ID, CWE, code location)
- Countermeasure summary (what to do)
- Risk reduction (from X to Y on the risk matrix)
- Implementation effort estimate
- Dependencies (must item A be completed before item B?)
- Residual benefits (cross-cutting security improvements)
- Acceptance criteria (how to verify the fix is effective)

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Context Integration and Risk Assessment (start here):**
- Review all prior stage outputs to establish your analytical foundation:
  - From Stage 1: Business objectives, data classifications, and compliance \
requirements that define what impact means in business terms
  - From Stage 2: Technology stack and deployment context that inform \
implementation feasibility of countermeasures
  - From Stage 3: Data flows, trust boundaries, and asset inventory that \
determine blast radius and cross-cutting dependencies
  - From Stage 4: Threat inventory providing the threat landscape context
  - From Stage 5: Vulnerability inventory with CVSS scores, CWE classifications, \
and initial remediation guidance — the foundation for countermeasure identification
  - From Stage 6: Attack trees, feasibility assessments, and impact narratives — \
the basis for risk qualification and quantification
- Qualify and quantify business impact for every attack scenario (Pillar 1)
- Build a tracking list: every Stage 6 attack scenario and Stage 5 vulnerability \
that must have countermeasures

**Phase 2 — Countermeasure Development and Residual Risk Analysis:**
- Identify specific countermeasures for each vulnerability and attack path (Pillar 2)
- Assess residual risk after countermeasures (Pillar 3)
- Analyze cost-effectiveness trade-offs and identify residual benefits (Pillar 4)
- Validate that every Stage 5 vulnerability has an associated countermeasure or \
explicit acceptance rationale

**Phase 3 — Roadmap Synthesis and Completeness Validation:**
- Prioritize remediation items into P0-P3 tiers (Pillar 5)
- Verify every Stage 6 attack scenario has a risk assessment
- Verify every Stage 5 vulnerability has a countermeasure or acceptance rationale
- Verify residual benefits are documented for cross-cutting countermeasures
- Consolidate findings and ensure cross-referencing is complete

## OUTPUT REQUIREMENTS

Write your analysis to `threatmodel/07-risk-and-impact-analysis.md`. Create the \
`threatmodel/` directory if it does not already exist.

Structure your output with the five pillar headings as top-level sections \
(## Business Impact Qualification and Quantification, ## Countermeasure \
Identification, ## Residual Risk Assessment, ## Mitigation Effectiveness vs Cost \
Analysis, ## Prioritized Remediation Roadmap). Within each section, organize your \
findings naturally based on what you discover — add subsections, tables, or lists \
as appropriate.

**For each attack scenario risk assessment, include:**
- Impact qualification (Critical/High/Medium/Low) with justification
- Impact quantification with data exposure scope, financial exposure, and \
operational impact estimates
- Likelihood assessment combining Stage 6 feasibility and Stage 5 CVSS
- Risk matrix rating

**For each countermeasure, include:**
- What it addresses (vulnerability and attack path references)
- Implementation approach with specific technical details
- Effort estimate and dependencies
- Countermeasure category (preventive, detective, corrective, compensating)

**For each residual risk, include:**
- Post-countermeasure vulnerability and attack surface status
- Residual impact and likelihood reassessment
- Updated risk rating with comparison to pre-countermeasure rating
- Risk acceptance criteria where applicable

**For the cost-effectiveness analysis, include:**
- Risk reduction magnitude and coverage breadth for each countermeasure
- Cost dimensions (implementation, operational, opportunity, introduction risk)
- Cost-effectiveness ranking (quick wins, strategic investments, diminishing \
returns, maintenance items)
- Residual benefits for cross-cutting countermeasures

**For the remediation roadmap, include:**
- Priority tiers (P0-P3) with clear criteria for each tier
- Per-item details: vulnerability reference, countermeasure, risk reduction, \
effort, dependencies, residual benefits, acceptance criteria
- Dependency ordering within and across tiers

**Completeness requirements:**
- Every attack scenario from Stage 6 must have a risk assessment
- Every confirmed vulnerability from Stage 5 must have a countermeasure or \
acceptance rationale
- Residual risk must be assessed for every countermeasure
- Cost-effectiveness analysis must cover all significant countermeasures
- Remediation roadmap must include all countermeasures organized by priority
- Residual benefits must be documented for countermeasures with cross-cutting impact

**Quality standards:**
- Ground all risk assessments in evidence from prior stages — reference specific \
attack trees, CVSS scores, data classifications, and business objectives
- Countermeasures must be specific and actionable — "implement input validation" \
is insufficient; "add parameterized query in api/users.py:34 replacing string \
interpolation for user_id parameter" is actionable
- Cost estimates must be realistic relative to the complexity of the change
- The remediation roadmap must be immediately usable by a development team — \
each item should be convertible into a work ticket
- Be specific: "Apply parameterized queries to resolve CWE-89 in api/users.py:34, \
reducing risk from Critical to Low. Effort: 2 hours. Residual benefit: also \
protects admin/reports.py:112 which uses the same query builder" rather than \
"fix SQL injection vulnerabilities"

Your risk and impact analysis is the culmination of the entire PASTA process. The \
remediation roadmap you produce will directly determine which security improvements \
the development team implements and in what order. Thorough, evidence-based risk \
analysis with actionable countermeasures and honest residual risk assessment is the \
difference between a threat model that drives real security improvement and one \
that sits on a shelf.
"""


def build_prompt(context: RiskImpactContext) -> str:
    """Build the complete Stage 7 prompt with prior stage injection.

    Args:
        context: RiskImpactContext with optional stage_01_output through
                 stage_06_output markdown from prior stages.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.stage_01_output or None
    stage_02_output = context.stage_02_output or None
    stage_03_output = context.stage_03_output or None
    stage_04_output = context.stage_04_output or None
    stage_05_output = context.stage_05_output or None
    stage_06_output = context.stage_06_output or None

    # Build prior stages section
    if any(
        [
            stage_01_output,
            stage_02_output,
            stage_03_output,
            stage_04_output,
            stage_05_output,
            stage_06_output,
        ]
    ):
        parts = [
            "## PRIOR STAGE FINDINGS\n",
            "The following outputs from prior stages provide the context that must "
            "inform your risk and impact analysis. Use Stage 1 business objectives "
            "and data classifications to ground impact assessment in business terms. "
            "Use Stage 2 technical scope to inform countermeasure feasibility. Use "
            "Stage 3 decomposition for data flows and trust boundaries that determine "
            "blast radius. Use Stage 4 threat inventory for threat landscape context. "
            "Use Stage 5 vulnerability findings as the foundation for countermeasure "
            "identification — every confirmed vulnerability must have an associated "
            "countermeasure or acceptance rationale. Use Stage 6 attack trees and "
            "feasibility assessments as the basis for risk qualification and "
            "quantification.\n",
            "<prior_stages>",
        ]

        if stage_01_output:
            parts.append("<stage_01_objectives>")
            parts.append(stage_01_output)
            parts.append("</stage_01_objectives>")

        if stage_02_output:
            parts.append("<stage_02_technical_scope>")
            parts.append(stage_02_output)
            parts.append("</stage_02_technical_scope>")

        if stage_03_output:
            parts.append("<stage_03_decomposition>")
            parts.append(stage_03_output)
            parts.append("</stage_03_decomposition>")

        if stage_04_output:
            parts.append("<stage_04_threat_analysis>")
            parts.append(stage_04_output)
            parts.append("</stage_04_threat_analysis>")

        if stage_05_output:
            parts.append("<stage_05_vulnerability>")
            parts.append(stage_05_output)
            parts.append("</stage_05_vulnerability>")

        if stage_06_output:
            parts.append("<stage_06_attack_modeling>")
            parts.append(stage_06_output)
            parts.append("</stage_06_attack_modeling>")

        parts.append("</prior_stages>")
        prior_stages_section = "\n".join(parts)
    else:
        prior_stages_section = ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    return prompt
