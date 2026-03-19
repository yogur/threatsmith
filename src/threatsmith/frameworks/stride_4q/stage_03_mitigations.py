"""4QF+STRIDE Stage 3 — Mitigations prompt template."""

from threatsmith.frameworks.types import StageContext

STAGE_PROMPT = """\
You are a threat modeling analyst performing 4QF+STRIDE Stage 3 — Mitigations. \
This stage answers the third question of the Four Question Framework: \
"What are we going to do about it?" Your analysis maps countermeasures to every \
threat identified in Stage 2, assesses existing controls, identifies gaps, and \
provides actionable implementation recommendations.

Your task is to analyze the codebase in the current working directory and produce \
a comprehensive mitigation plan addressing every threat from the Stage 2 Threat \
Identification.

{prior_stages_section}

## ANALYSIS APPROACH

### Countermeasure Identification Per Threat

For every threat documented in Stage 2, identify one or more countermeasures:

- **Preventive controls:** Measures that eliminate or reduce the likelihood of the \
threat being realized (e.g., input validation, parameterized queries, strong \
authentication, encryption at rest and in transit).

- **Detective controls:** Measures that detect when a threat is being exploited or \
has been exploited (e.g., intrusion detection, anomaly monitoring, audit logging, \
integrity checks).

- **Corrective controls:** Measures that limit damage and restore normal operations \
after exploitation (e.g., incident response procedures, automated rollback, backup \
and recovery, circuit breakers).

Map each countermeasure to the specific STRIDE category and component(s) it \
addresses. A single countermeasure may address multiple threats.

### Existing Controls Assessment

Examine the codebase to identify controls already in place:

- Authentication and authorization mechanisms currently implemented
- Input validation and sanitization patterns in use
- Encryption and data protection measures deployed
- Logging and monitoring capabilities present
- Error handling and failure modes implemented
- Rate limiting, throttling, and abuse prevention measures
- Dependency management and update practices

For each existing control, assess its effectiveness:
- Is it correctly implemented?
- Does it cover all relevant entry points and data flows?
- Are there bypasses or weaknesses in the implementation?
- Does it meet industry standards and best practices?

### Gap Analysis

Compare the threats from Stage 2 against existing controls:

- **Covered threats:** Threats adequately addressed by existing controls — document \
the control and its effectiveness.
- **Partially covered threats:** Threats where controls exist but are incomplete, \
misconfigured, or insufficient — document what is missing.
- **Uncovered threats:** Threats with no existing countermeasure — these require new \
controls.

### Implementation Recommendations

For each gap (partially covered or uncovered threat), provide:

- **Recommended countermeasure:** Specific, actionable recommendation with enough \
detail for a developer to implement it. Reference specific files, functions, or \
configurations that need to change.

- **Effort estimate:** Categorize implementation effort as:
  - **Low** — Configuration change, library upgrade, or minor code modification \
(hours to a day)
  - **Medium** — New component, significant refactoring, or integration work \
(days to a week)
  - **High** — Architectural change, new infrastructure, or cross-cutting \
modification (weeks)

- **Priority:** Rank based on the threat severity from Stage 2 and the effort \
required. Use P0 (critical, implement immediately), P1 (high, implement soon), \
P2 (medium, plan for next cycle), P3 (low, backlog).

- **Implementation guidance:** Specific steps, patterns, libraries, or \
configurations to use. Reference concrete code locations where changes should \
be made.

### Residual Risk Assessment

For each threat, document the residual risk after proposed mitigations:

- What risk remains even after the recommended countermeasures are implemented?
- Are there threats that cannot be fully mitigated and must be accepted?
- What compensating controls exist for accepted risks?
- Are there dependencies on external parties (cloud providers, third-party \
services) for risk reduction?

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Context Integration (start here):**
- Review the Stage 1 System Model to understand the architecture and components
- Review the Stage 2 Threat Identification to catalog all identified threats
- Build a complete inventory of threats requiring mitigation

**Phase 2 — Codebase Control Assessment:**
- Examine authentication and authorization implementations
- Review input validation and output encoding patterns
- Assess encryption, key management, and secrets handling
- Evaluate logging, monitoring, and alerting configurations
- Check dependency management and security update practices
- Identify security patterns and anti-patterns in the codebase

**Phase 3 — Gap Analysis and Recommendations:**
- Map existing controls to identified threats
- Identify coverage gaps
- Develop specific, prioritized recommendations
- Assess residual risk for each threat

## OUTPUT REQUIREMENTS

Write your analysis to `{output_dir}03-mitigations.md`. Create the \
`{output_dir}` directory if it does not already exist.

Structure your output with clear sections:

1. **Executive Summary** — High-level overview of the mitigation posture: how many \
threats are covered, partially covered, and uncovered; overall risk reduction \
assessment.

2. **Existing Controls Inventory** — Document all security controls found in the \
codebase with effectiveness assessment.

3. **Gap Analysis** — Organized by threat, showing current state, gaps, and \
recommended countermeasures.

4. **Prioritized Recommendations** — All recommendations sorted by priority \
(P0 → P3) with effort estimates and implementation guidance.

5. **Residual Risk Summary** — Consolidated view of remaining risks after all \
recommended mitigations, including accepted risks with justification.

**Quality standards:**
- Every threat from Stage 2 must appear in the mitigation analysis — no threats \
should be silently dropped
- Recommendations must be specific and actionable — reference exact files, \
functions, and configurations
- Effort estimates must be realistic — do not underestimate architectural changes
- Distinguish between "quick wins" (low effort, high impact) and strategic \
improvements (high effort, high impact)
- Ground all assessments in evidence from the codebase — avoid generic security \
advice not tied to observed code patterns

Your mitigation plan provides the actionable remediation roadmap. Stage 4 \
(Validation) will verify completeness and assess the overall quality of this \
threat model.
"""


def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
    """Build the complete Stage 3 prompt with prior stage outputs.

    Args:
        context: StageContext with optional prior_outputs containing
                 "stage_01_output" and "stage_02_output" markdown.
        output_dir: Output directory for deliverables (defaults to "threatmodel").
                   Accepts with or without trailing slash.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.prior_outputs.get("stage_01_output") or None
    stage_02_output = context.prior_outputs.get("stage_02_output") or None
    normalized_dir = output_dir.rstrip("/") + "/"

    # Build prior stages section
    prior_parts = []
    if stage_01_output or stage_02_output:
        prior_parts.append("## PRIOR STAGE FINDINGS\n")
        prior_parts.append(
            "The following outputs from prior stages provide the system model and "
            "threat inventory that must inform your mitigation analysis. Every "
            "threat identified in Stage 2 must be addressed with countermeasures, "
            "gap analysis, and residual risk assessment.\n"
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

        prior_parts.append("</prior_stages>")

    prior_stages_section = "\n".join(prior_parts) if prior_parts else ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    return prompt.replace("{output_dir}", normalized_dir)
