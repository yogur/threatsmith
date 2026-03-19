"""4QF+STRIDE Stage 4 — Validation prompt template."""

from threatsmith.frameworks.types import StageContext

STAGE_PROMPT = """\
You are a threat modeling analyst performing 4QF+STRIDE Stage 4 — Validation. \
This stage answers the fourth question of the Four Question Framework: \
"Did we do a good job?" Your analysis verifies the completeness and quality of \
the threat model produced in Stages 1–3, identifies remaining gaps, documents \
accepted risks with justification, and recommends next steps and a review cadence.

Your task is to analyze the codebase in the current working directory alongside \
the prior stage outputs to validate the threat model's completeness and quality.

{prior_stages_section}

## ANALYSIS APPROACH

### Component Coverage Verification

Verify that the Stage 1 System Model comprehensively captured the system:

- Are all significant components, services, and subsystems accounted for?
- Are all external dependencies and third-party integrations represented?
- Are all data stores and their sensitivity classifications documented?
- Are all entry points and external-facing interfaces identified?
- Are trust boundaries correctly placed and complete?
- Are there components in the codebase not represented in the system model?

Cross-reference the system model against the actual codebase to identify any \
components, data flows, or trust boundaries that were missed.

### STRIDE Category Coverage Verification

Verify that Stage 2 Threat Identification systematically covered all STRIDE \
categories across relevant components:

- **Spoofing:** Were authentication boundaries and identity verification \
points analyzed for impersonation risks?
- **Tampering:** Were data integrity checks assessed for all data stores, \
data flows, and configuration files?
- **Repudiation:** Were audit logging and non-repudiation controls evaluated \
for all security-relevant actions?
- **Information Disclosure:** Were data exposure risks assessed for all \
sensitive data at rest, in transit, and in logs?
- **Denial of Service:** Were availability threats identified for all \
external-facing services and shared resources?
- **Elevation of Privilege:** Were authorization boundaries and privilege \
escalation paths analyzed for all roles and access levels?

Identify any component-category combinations that were not analyzed and should \
have been.

### Mitigation Completeness for High-Priority Threats

Verify that Stage 3 Mitigations adequately addressed the identified threats:

- Do all P0 and P1 threats have specific, actionable countermeasures?
- Are the proposed mitigations technically sound and implementable?
- Are effort estimates realistic given the codebase complexity?
- Are there threats marked as mitigated but with weak or partial controls?
- Are there dependencies between mitigations that could create \
implementation bottlenecks?

### Remaining Gaps

Document any gaps discovered during validation:

- Components missing from the system model
- STRIDE categories not applied to relevant components
- Threats without adequate mitigation plans
- Mitigations that appear insufficient or incorrectly scoped
- Attack paths not considered in the threat analysis
- Environmental or deployment-specific risks not addressed

### Accepted Risks with Justification

For each risk that cannot or should not be mitigated, document:

- **Risk description:** What is the specific risk being accepted?
- **Justification:** Why is this risk being accepted? (cost-benefit, low \
likelihood, compensating controls, business decision, etc.)
- **Conditions:** Under what conditions should this accepted risk be \
re-evaluated? (business growth, regulatory changes, architecture changes, etc.)
- **Compensating controls:** What alternative measures reduce the impact if \
the risk materializes?
- **Risk owner:** Who should be accountable for monitoring this accepted risk?

### Recommended Next Steps and Review Cadence

Provide actionable recommendations for maintaining the threat model:

- **Immediate actions:** Critical gaps that must be addressed before the \
threat model can be considered complete.
- **Short-term actions:** Improvements to implement within the next \
development cycle.
- **Review triggers:** Events that should trigger a threat model update \
(new features, architecture changes, security incidents, dependency updates, \
regulatory changes).
- **Review cadence:** Recommended periodic review schedule (quarterly, \
semi-annually, or annually) based on the system's risk profile and rate \
of change.
- **Process improvements:** Suggestions for improving the threat modeling \
process itself based on gaps found during this validation.

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Prior Stage Review (start here):**
- Review Stage 1 System Model for completeness against the codebase
- Review Stage 2 Threat Identification for STRIDE coverage breadth
- Review Stage 3 Mitigations for adequacy and actionability

**Phase 2 — Codebase Cross-Reference:**
- Walk the codebase to identify components, data flows, or entry points \
missing from the system model
- Check for security-relevant patterns not captured in the threat analysis
- Verify that mitigation recommendations reference actual code locations

**Phase 3 — Gap Synthesis and Recommendations:**
- Consolidate all identified gaps into a structured assessment
- Document accepted risks with justification
- Formulate next steps and review cadence

## OUTPUT REQUIREMENTS

Write your analysis to `{output_dir}04-validation.md`. Create the \
`{output_dir}` directory if it does not already exist.

Structure your output with clear sections:

1. **Validation Summary** — Overall assessment of the threat model's \
completeness and quality. State whether the threat model is sufficient, \
needs minor improvements, or has significant gaps.

2. **Component Coverage Assessment** — Results of cross-referencing the \
system model against the codebase, listing any missing components or \
data flows.

3. **STRIDE Coverage Assessment** — Matrix or table showing which STRIDE \
categories were applied to which components, highlighting gaps.

4. **Mitigation Adequacy Assessment** — Evaluation of mitigation completeness \
for high-priority threats, identifying weak or missing countermeasures.

5. **Remaining Gaps** — Consolidated list of all gaps found during validation, \
organized by severity.

6. **Accepted Risks** — Documented risks with justification, conditions for \
re-evaluation, and compensating controls.

7. **Recommended Next Steps** — Prioritized actions for completing and \
maintaining the threat model, including review cadence.

**Quality standards:**
- Every gap identified must include a specific recommendation for remediation
- Accepted risks must have documented justification — no silent risk acceptance
- Coverage assessments must be evidence-based, referencing specific components \
and STRIDE categories
- Recommendations must be actionable and prioritized
- The validation must add value beyond simply restating prior stage outputs — \
identify genuine gaps and improvements

This validation stage closes the Four Question Framework loop. The consolidated \
report (Stage 5) will combine all four stages into a single executive deliverable.
"""


def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
    """Build the complete Stage 4 prompt with prior stage outputs.

    Args:
        context: StageContext with optional prior_outputs containing
                 "stage_01_output", "stage_02_output", and "stage_03_output"
                 markdown.
        output_dir: Output directory for deliverables (defaults to "threatmodel").
                   Accepts with or without trailing slash.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.prior_outputs.get("stage_01_output") or None
    stage_02_output = context.prior_outputs.get("stage_02_output") or None
    stage_03_output = context.prior_outputs.get("stage_03_output") or None
    normalized_dir = output_dir.rstrip("/") + "/"

    # Build prior stages section
    prior_parts = []
    if stage_01_output or stage_02_output or stage_03_output:
        prior_parts.append("## PRIOR STAGE FINDINGS\n")
        prior_parts.append(
            "The following outputs from prior stages constitute the threat model "
            "being validated. Review each stage critically for completeness, "
            "accuracy, and coverage gaps.\n"
        )
        prior_parts.append("<prior_stages>")

        if stage_01_output:
            prior_parts.append("<stage_01_system_model>")
            prior_parts.append(stage_01_output)
            prior_parts.append("</stage_01_system_model>")

        if stage_02_output:
            prior_parts.append("<stage_02_threat_identification>")
            prior_parts.append(stage_02_output)
            prior_parts.append("</stage_02_threat_identification>")

        if stage_03_output:
            prior_parts.append("<stage_03_mitigations>")
            prior_parts.append(stage_03_output)
            prior_parts.append("</stage_03_mitigations>")

        prior_parts.append("</prior_stages>")

    prior_stages_section = "\n".join(prior_parts) if prior_parts else ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    return prompt.replace("{output_dir}", normalized_dir)
