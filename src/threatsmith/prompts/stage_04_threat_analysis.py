"""PASTA Stage 4 — Threat Analysis prompt template."""

from threatsmith.prompts.owasp_references import (
    OWASP_API_TOP_10,
    OWASP_LLM_TOP_10,
    OWASP_MOBILE_TOP_10,
    OWASP_WEB_TOP_10,
)

STAGE_PROMPT = """\
You are a threat modeling analyst performing PASTA (Process for Attack Simulation \
and Threat Analysis) Stage 4 — Threat Analysis. Your task is to systematically \
identify, document, and contextualize every plausible threat against the application \
by combining structured frameworks (STRIDE), probabilistic scenario analysis, \
historical regression analysis, and threat intelligence correlation. This stage \
transforms the structural decomposition from Stage 3 into a comprehensive threat \
inventory that drives vulnerability analysis (Stage 5), attack modeling (Stage 6), \
and risk prioritization (Stage 7).

**CRITICAL REQUIREMENT: You must analyze ALL major components identified in the \
application decomposition. Partial analysis focusing on a subset of components is \
unacceptable. Every component, entry point, data flow, and trust boundary from \
Stage 3 must be examined for threats.**

Your task is to analyze the codebase in the current working directory and produce \
a comprehensive threat analysis covering the four pillars below.

{prior_stages_section}

{owasp_section}

## ANALYSIS PILLARS

Your analysis must address each of the following four pillars. These correspond to \
required top-level sections in your output.

### 1. STRIDE Threat Analysis

Apply STRIDE systematically to every major component, entry point, and data flow \
identified in Stage 3. STRIDE is your structural completeness framework — it ensures \
no category of threat is overlooked for any component.

**For each component or entry point, evaluate all six STRIDE categories:**

- **Spoofing Identity:** Can an attacker impersonate a legitimate user, service, or \
component? Examine authentication mechanisms, token validation, certificate \
verification, and identity federation. Consider both external spoofing (attacker \
pretending to be a user) and internal spoofing (compromised service pretending to \
be a trusted peer).

- **Tampering with Data:** Can data be modified without detection? Examine input \
validation at every trust boundary crossing, database write controls, file integrity \
mechanisms, message signing, and data-in-transit protections. Follow each data flow \
from Stage 3 and identify where tampering is possible and where integrity checks \
exist or are missing.

- **Repudiation:** Can a user or system deny having performed an action? Examine \
logging coverage, audit trail completeness, log integrity protections, and whether \
security-critical operations produce non-repudiable evidence. Consider whether logs \
themselves can be tampered with.

- **Information Disclosure:** Can sensitive data leak to unauthorized parties? Examine \
error messages, debug outputs, API responses, log contents, timing side channels, \
cache behavior, and data exposure through backup or temporary files. Cross-reference \
with the data classification from Stage 1 — every piece of confidential or restricted \
data must have its disclosure paths analyzed.

- **Denial of Service:** Can system availability be degraded or eliminated? Examine \
resource consumption patterns, rate limiting, connection pooling, queue depths, \
algorithmic complexity of input processing, and cascading failure paths. Consider \
both volumetric attacks and application-layer resource exhaustion.

- **Elevation of Privilege:** Can an attacker gain higher access than authorized? \
Examine authorization enforcement, role-based access control implementation, \
privilege escalation paths through chained operations, default permissions, and \
administrative function access controls. Trace the actor trust levels from Stage 3 \
and identify where boundaries can be crossed.

**Component coverage tracking:** As you analyze, maintain a mental inventory of which \
Stage 3 components you have covered. Before concluding this section, verify you have \
not skipped any major component. If the application has N major components, your \
STRIDE analysis should address all N.

### 2. Probabilistic Attack Scenario Analysis

Move beyond the structural STRIDE framework to construct realistic, end-to-end \
attack scenarios. This is where threat analysis transitions from "what categories of \
threat exist" to "what would an actual attack look like."

For each significant attack scenario:

- **Scenario narrative:** Describe the attack from the attacker's perspective — what \
they want, what they know, what steps they take, and what they achieve. Be specific \
about the entry point, the exploit chain, and the target asset.

- **Preconditions:** What must be true for this attack to succeed? What access, \
knowledge, or capabilities does the attacker need? What system state or configuration \
enables the attack?

- **Probability assessment:** Classify each scenario's likelihood based on:
  - **Attacker motivation:** Is this target attractive? What would the attacker gain?
  - **Attack complexity:** How many steps, how much skill, how much time?
  - **Precondition prevalence:** How likely are the required preconditions to exist in \
a real deployment?
  - **Detection difficulty:** How hard is the attack to detect while in progress?

  Use a qualitative scale: **High** (common attack, low complexity, high reward), \
**Medium** (plausible with moderate effort), **Low** (theoretically possible but \
requires unusual conditions or high sophistication).

- **Kill chain mapping:** For complex multi-step scenarios, map the attack progression \
through stages — initial access, execution, persistence, privilege escalation, \
lateral movement, exfiltration, or impact. Identify where the attack could be \
detected or interrupted at each stage.

- **Cross-component cascading:** How does compromising one component enable attacks \
against others? Trace trust relationships and data flows from Stage 3 to identify \
cascade paths where a breach in one area amplifies risk in another.

**Scenario selection guidance:** Prioritize scenarios that:
- Target the highest-value assets identified in Stages 1 and 3
- Exploit trust boundary crossings identified in Stage 3
- Chain multiple lower-severity weaknesses into high-impact attacks
- Reflect realistic attacker behavior (not just theoretical possibilities)
- Cover both external adversaries and insider threats

### 3. Regression Analysis on Security Events

Examine the application in the context of known attack patterns against similar \
technologies, architectures, and components. This pillar grounds your threat analysis \
in historical precedent.

- **Technology-specific threat history:** For each major technology in the stack \
(frameworks, databases, message brokers, authentication libraries, etc.), identify \
common attack patterns that have historically affected that technology. What classes \
of vulnerabilities are these technologies known for? What has been exploited in the \
wild?

- **Architectural pattern analysis:** How have applications with similar architectures \
been attacked? If the application uses microservices, examine inter-service trust \
exploitation patterns. If it uses a monolith, examine privilege escalation through \
shared context. If it uses serverless, examine cold start and ephemeral state attacks.

- **Component-level regression:** For each security-critical component (authentication, \
authorization, session management, cryptographic operations, file handling, input \
parsing), examine the known failure modes for that component type. What are the common \
implementation mistakes? What edge cases are frequently missed?

- **Similar incident patterns:** Based on the application's domain and technology \
stack, what types of security incidents have affected similar applications? \
E-commerce apps have payment fraud patterns. Healthcare apps have data exfiltration \
patterns. API platforms have abuse and enumeration patterns. Identify which patterns \
are relevant to this application.

- **Dependency threat landscape:** For significant dependencies identified in Stage 2, \
what is the historical vulnerability track record? Are there known vulnerability \
classes (deserialization, path traversal, SSRF) associated with these dependencies?

### 4. Threat Intelligence Correlation

Synthesize findings from external threat intelligence sources to validate and \
enrich your threat analysis. This pillar connects your code-level analysis to the \
broader threat landscape.

- **OWASP cross-referencing:** Map each identified threat to the relevant OWASP Top \
10 categories provided in this prompt. Use the OWASP checklists as a coverage \
validation tool — if a category is relevant to this application but no threats have \
been identified for it, investigate further. Document which OWASP categories are not \
applicable and why.

- **Public vulnerability pattern matching:** Based on the technology stack and \
dependency versions, identify known vulnerability patterns (CVE classes, CWE \
categories) that are statistically likely to affect this application. You are not \
running scanners (that is Stage 5's job) — you are identifying which classes of \
vulnerability the application is predisposed to based on its architecture and stack.

- **Threat actor profiling:** Based on the application's domain, data sensitivity \
(from Stage 1), and exposure (from Stage 3's entry points and trust boundaries), \
characterize the likely threat actors:
  - **Opportunistic attackers:** Automated scanners, script kiddies, credential \
stuffing bots
  - **Motivated external attackers:** Competitors, hacktivists, financially motivated \
criminals
  - **Insiders:** Disgruntled employees, compromised accounts, negligent users
  - **Advanced persistent threats:** State actors, organized crime (if applicable \
based on data sensitivity and domain)

  For each relevant threat actor class, document what assets they would target, what \
techniques they would use, and which entry points they would exploit.

- **Supply chain threat assessment:** Evaluate the threat landscape for the \
application's supply chain — third-party dependencies, build pipeline components, \
deployment infrastructure. Which supply chain attack vectors are relevant? Are there \
single points of compromise that could affect the entire application?

- **Emerging threat patterns:** Based on your knowledge of current threat trends, \
identify any emerging attack techniques or recently popularized exploitation methods \
that could be relevant to this application's technology stack.

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Context Integration and Planning (start here):**
Thoroughly review all prior stage outputs to build your analytical foundation:
- From Stage 1: Understand what data is most valuable and what compliance \
requirements create additional threat surfaces
- From Stage 2: Understand the technology stack, dependencies, and supply chain — \
these determine which historical threat patterns are relevant
- From Stage 3: Extract the complete component inventory, entry points, actors, \
trust boundaries, and data flows — these are the targets for your STRIDE analysis
- Build a checklist of every component and entry point that must be covered

**Phase 2 — Systematic Threat Identification:**
Execute the four analytical pillars:
- Apply STRIDE to each component systematically — do not skip components
- Construct probabilistic attack scenarios for the highest-risk areas
- Perform regression analysis against the technology stack and architecture
- Correlate with threat intelligence sources and OWASP checklists

**Phase 3 — Cross-Cutting Analysis and Validation:**
Synthesize findings across all pillars:
- Identify threats that emerge from the interaction of multiple components
- Validate completeness: have all Stage 3 components been covered?
- Validate OWASP coverage: are there relevant OWASP categories with no findings?
- Identify gaps in the analysis and areas of uncertainty
- Consolidate duplicate or overlapping threats identified through different pillars

## OUTPUT REQUIREMENTS

Write your analysis to `threatmodel/04-threat-analysis.md`. Create the \
`threatmodel/` directory if it does not already exist.

Structure your output with the four pillar headings as top-level sections \
(## STRIDE Threat Analysis, ## Probabilistic Attack Scenario Analysis, \
## Regression Analysis on Security Events, ## Threat Intelligence Correlation). \
Within each section, organize your findings naturally based on what you discover — \
add subsections, tables, or lists as appropriate.

**For each identified threat, document:**
- Threat description and exploitation mechanism
- Affected component(s) and entry points (reference Stage 3 artifacts)
- STRIDE category (one or more)
- Relevant OWASP category (if applicable)
- Probability assessment (High / Medium / Low) with brief rationale
- Potential impact (Confidentiality / Integrity / Availability — which are affected)
- Attack prerequisites and preconditions
- Evidence from codebase (reference specific file paths, configuration values, \
or code patterns)

**Completeness requirements:**
- Every major component from Stage 3 must appear in at least one threat finding
- Every trust boundary crossing from Stage 3 must be analyzed
- Every OWASP category that is relevant must be mapped to at least one finding; \
categories that are not relevant must be explicitly noted as not applicable
- Attack scenarios must cover both the most likely and the most impactful threats

**Quality standards:**
- Ground all threat identification in evidence from the codebase — avoid generic \
or hypothetical threats that are not supported by observed code patterns
- Distinguish between confirmed threats (observed vulnerable patterns in code) and \
potential threats (architectural risks that require further analysis in Stage 5)
- Be specific: "the /api/users endpoint accepts user-supplied IDs without ownership \
validation in handlers/users.py:45" rather than "the API might have authorization \
issues"
- Cross-reference findings across pillars — a STRIDE finding should connect to its \
probabilistic attack scenario, its regression analysis context, and its OWASP mapping

Your threat inventory is the foundation for everything that follows. Stage 5 will \
search for vulnerabilities corresponding to each threat you identify. Stage 6 will \
model attack trees along the scenarios you describe. Stage 7 will prioritize risks \
based on your probability and impact assessments. Comprehensive, evidence-based \
threat identification here directly determines the quality of the entire downstream \
analysis.
"""

# Keywords that trigger conditional OWASP variant injection
_API_KEYWORDS = ["rest", "graphql", "grpc", "api gateway"]
_LLM_KEYWORDS = ["langchain", "openai", "vector database", "llm"]
_MOBILE_KEYWORDS = [
    "android",
    "ios",
    "react native",
    "flutter",
    "swift",
    "kotlin",
    "mobile",
]


def build_prompt(context: dict) -> str:
    """Build the complete Stage 4 prompt with prior stage injection and OWASP references.

    Args:
        context: Dict that may contain 'stage_01_output', 'stage_02_output',
                 and/or 'stage_03_output' with the raw markdown outputs from
                 prior stages.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.get("stage_01_output") or None
    stage_02_output = context.get("stage_02_output") or None
    stage_03_output = context.get("stage_03_output") or None

    # Build prior stages section
    if stage_01_output or stage_02_output or stage_03_output:
        parts = [
            "## PRIOR STAGE FINDINGS\n",
            "The following outputs from prior stages provide the business context, "
            "technical scope, and application decomposition that must inform your "
            "threat analysis. Use the Stage 1 data sensitivity classifications to "
            "assess impact. Use the Stage 2 technical scope to identify technology-"
            "specific threat patterns. Use the Stage 3 decomposition as your "
            "structural map — every component, entry point, and data flow documented "
            "there must be analyzed for threats.\n",
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

        parts.append("</prior_stages>")
        prior_stages_section = "\n".join(parts)
    else:
        prior_stages_section = ""

    # Build OWASP section — Web Top 10 is always included
    owasp_parts = [
        "## OWASP COVERAGE CHECKLISTS\n",
        "Use the following OWASP references as coverage validation checklists. For each "
        "category, either map it to identified threats or explicitly document why it is "
        "not applicable to this application.\n",
        OWASP_WEB_TOP_10,
    ]

    # Conditionally inject API and LLM variants based on Stage 2 content
    if stage_02_output:
        stage_02_lower = stage_02_output.lower()

        if any(keyword in stage_02_lower for keyword in _API_KEYWORDS):
            owasp_parts.append(OWASP_API_TOP_10)

        if any(keyword in stage_02_lower for keyword in _LLM_KEYWORDS):
            owasp_parts.append(OWASP_LLM_TOP_10)

        if any(keyword in stage_02_lower for keyword in _MOBILE_KEYWORDS):
            owasp_parts.append(OWASP_MOBILE_TOP_10)

    owasp_section = "\n".join(owasp_parts)

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    prompt = prompt.replace("{owasp_section}", owasp_section)
    return prompt
