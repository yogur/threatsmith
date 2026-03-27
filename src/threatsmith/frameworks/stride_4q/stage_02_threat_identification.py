"""4QF+STRIDE Stage 2 — Threat Identification prompt template."""

from threatsmith.frameworks.references.scanner_snippets import SCANNER_SNIPPETS
from threatsmith.frameworks.types import StageContext

STAGE_PROMPT = """\
You are a threat modeling analyst performing 4QF+STRIDE Stage 2 — Threat \
Identification. This stage answers the second question of the Four Question \
Framework: "What can go wrong?" Your analysis systematically identifies threats \
across every component documented in the Stage 1 System Model using STRIDE as \
the structural completeness framework.

Your task is to analyze the codebase in the current working directory and produce \
a comprehensive threat identification covering every component, data flow, and \
trust boundary from Stage 1.

{prior_stages_section}

{references_section}

{scanner_section}

## ANALYSIS APPROACH

### Systematic STRIDE Analysis Per Component

Apply all six STRIDE categories to every major component, entry point, data flow, \
and trust boundary identified in Stage 1. STRIDE ensures no category of threat is \
overlooked for any component.

**For each component or entry point, evaluate:**

- **Spoofing Identity:** Can an attacker impersonate a legitimate user, service, \
or component? Examine authentication mechanisms, token validation, certificate \
verification, and identity federation. Consider both external spoofing (attacker \
pretending to be a user) and internal spoofing (compromised service pretending to \
be a trusted peer).

- **Tampering with Data:** Can data be modified without detection? Examine input \
validation at every trust boundary crossing, database write controls, file integrity \
mechanisms, message signing, and data-in-transit protections. Follow each data flow \
from Stage 1 and identify where tampering is possible and where integrity checks \
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
administrative function access controls.

### Threat Scenario Construction

For each identified threat, construct a concrete threat scenario:

- **Attacker motivation:** Why would an attacker target this component? What is the \
value of the asset they would gain access to or compromise?

- **Attacker capability:** What skill level, tools, and access does the attacker need? \
Characterize as opportunistic (automated scanners, script kiddies), motivated \
(skilled external attacker), insider (legitimate access misuse), or advanced \
(nation-state, organized crime).

- **Attack narrative:** Describe the attack step-by-step — entry point, exploitation \
method, lateral movement if applicable, and end goal. Reference specific code paths, \
configurations, or architectural patterns from the codebase.

- **Impact assessment:** What is the concrete impact if this threat is realized? \
Categorize by Confidentiality, Integrity, and Availability. Estimate severity as \
Critical, High, Medium, or Low.

### Scanner Integration

If scanner context is provided in this prompt, integrate scanner findings into your \
threat analysis. Scanner results provide evidence for threats you identify and may \
reveal additional threats not apparent from code review alone. For each scanner \
finding, map it to the relevant STRIDE category and affected component.

### Coverage Validation

Use the OWASP Top 10 references provided in this prompt as coverage checklists. \
For each OWASP category:
- Map it to identified threats, OR
- Explicitly document why it is not applicable to this application

Ensure every component from Stage 1 appears in at least one threat finding. \
Partial analysis focusing on a subset of components is unacceptable.

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Context Integration (start here):**
- Thoroughly review the Stage 1 System Model to build your analytical foundation
- Extract the complete component inventory, entry points, actors, trust boundaries, \
and data flows — these are the targets for your STRIDE analysis
- Build a checklist of every component that must be covered
- Review any scanner context provided

**Phase 2 — Systematic Threat Identification:**
- Apply STRIDE to each component systematically — do not skip components
- Construct threat scenarios with attacker motivation and capability context
- Integrate scanner findings where available
- Cross-reference with OWASP checklists for coverage validation

**Phase 3 — Cross-Cutting Analysis:**
- Identify threats that emerge from the interaction of multiple components
- Validate completeness: have all Stage 1 components been covered?
- Identify threat chains where compromising one component enables attacks on others
- Consolidate duplicate or overlapping threats

## OUTPUT REQUIREMENTS

Write your analysis to `{output_dir}02-threat-identification.md`.

Structure your output with clear sections organized by component or by STRIDE \
category — whichever produces clearer coverage for the application under analysis.

**For each identified threat, document:**
- Threat title and STRIDE category (one or more)
- Affected component(s) and entry points (reference Stage 1 artifacts)
- Attacker motivation and required capability
- Attack scenario narrative with specific code references
- Relevant OWASP category (if applicable)
- Severity assessment (Critical / High / Medium / Low) with brief rationale
- Impact (Confidentiality / Integrity / Availability — which are affected)

**Quality standards:**
- Ground all threat identification in evidence from the codebase — avoid generic \
or hypothetical threats not supported by observed code patterns
- Distinguish between confirmed threats (observed vulnerable patterns in code) and \
potential threats (architectural risks requiring further analysis)
- Be specific: "the /api/users endpoint accepts user-supplied IDs without ownership \
validation in handlers/users.py:45" rather than "the API might have authorization issues"
- Every component from Stage 1 must appear in at least one threat finding

Your threat inventory is the foundation for Stage 3 (Mitigations). Every threat \
you identify here will be mapped to countermeasures and assessed for residual risk.
"""


def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
    """Build the complete Stage 2 prompt with prior stage output, references, and scanners.

    Args:
        context: StageContext with optional prior_outputs containing
                 "stage_01_output" markdown, references list with pre-resolved
                 STRIDE/OWASP reference strings, and optional scanners_available.
        output_dir: Output directory for deliverables (defaults to "threatmodel").
                   Accepts with or without trailing slash.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.prior_outputs.get("stage_01_output") or None
    normalized_dir = output_dir.rstrip("/") + "/"

    # Build prior stages section
    if stage_01_output:
        parts = [
            "## PRIOR STAGE FINDINGS\n",
            "The following output from Stage 1 provides the system model that must "
            "inform your threat identification. Every component, data flow, entry "
            "point, and trust boundary documented here must be systematically "
            "analyzed for threats using STRIDE.\n",
            "<prior_stages>",
            "<stage_01_system_model>",
            stage_01_output,
            "</stage_01_system_model>",
            "</prior_stages>",
        ]
        prior_stages_section = "\n".join(parts)
    else:
        prior_stages_section = ""

    # Build references section from pre-resolved references (STRIDE categories + OWASP)
    references = context.references or []

    if references:
        ref_parts = [
            "## REFERENCE CHECKLISTS\n",
            "Use the following references as systematic coverage checklists. For STRIDE "
            "categories, ensure every category is evaluated for every component. For "
            "OWASP categories, map each to identified threats or explicitly document "
            "why it is not applicable.\n",
        ]
        ref_parts.extend(references)
        references_section = "\n".join(ref_parts)
    else:
        references_section = ""

    # Build scanner section based on available scanners
    scanners_available = context.scanners_available or []

    if scanners_available:
        scanner_parts = [
            "## SCANNER INSTRUCTIONS\n",
            "The following security scanners are available on this system. Run each "
            "one against the codebase and integrate the results into your threat "
            "analysis. Scanner results provide automated evidence that complements "
            "your manual code analysis — they do not replace it.\n",
        ]

        for scanner_name in scanners_available:
            snippet = SCANNER_SNIPPETS.get(scanner_name)
            if snippet:
                scanner_parts.append(snippet)

        scanner_section = "\n".join(scanner_parts)
    else:
        scanner_section = ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    prompt = prompt.replace("{references_section}", references_section)
    prompt = prompt.replace("{scanner_section}", scanner_section)
    return prompt.replace("{output_dir}", normalized_dir)
