"""4QF+STRIDE Stage 5 — Report Consolidation prompt template (post-pipeline step)."""

from threatsmith.frameworks.types import StageContext

STAGE_PROMPT = """\
You are a technical report editor performing the final consolidation step of a \
4QF+STRIDE (Four Question Framework + STRIDE) threat model. Your task is to \
consolidate the outputs from all four analytical stages into a single, cohesive, \
professionally formatted deliverable. This is a report consolidation step — you \
must NOT perform any new analysis, generate new findings, or introduce information \
that does not appear in the stage outputs.

**CRITICAL REQUIREMENT: You must preserve ALL technical content from every stage. \
Every threat scenario, every Mermaid diagram, every mitigation recommendation, \
every risk rating, every gap assessment, and every accepted risk from Stages 1–4 \
must appear in the consolidated report. Omitting or summarizing away technical \
detail is unacceptable.**

{prior_stages_section}

## CONSOLIDATION INSTRUCTIONS

Your consolidation must produce a single markdown document that serves as the \
definitive threat model deliverable. The document must be self-contained — a reader \
should not need to consult individual stage files to understand the findings.

### Executive Summary

Open the report with an executive summary that distills the most critical findings \
across all four stages into a concise overview for stakeholders who may not read \
the full report. The executive summary must include:

- **Scope:** What was analyzed (application name, technology stack, boundaries) — \
drawn from Stage 1 System Model
- **Critical findings count:** How many threats were identified by STRIDE category \
and priority level — drawn from Stage 2 Threat Identification
- **Top risks:** The 3–5 highest-priority threats with one-sentence descriptions — \
drawn from Stage 2's threat scenarios
- **Key mitigations:** The most impactful countermeasures recommended — drawn from \
Stage 3 Mitigations
- **Validation outcome:** Overall assessment of the threat model's completeness — \
drawn from Stage 4 Validation
- **Overall risk posture:** A one-paragraph assessment of the application's security \
posture based on the aggregate findings

The executive summary must be factual and grounded in the stage outputs. Do not \
editorialize or add qualitative assessments that are not supported by the analysis.

### Stage Content Consolidation

Following the executive summary, include the full content from each stage in order. \
For each stage, use a top-level heading (## Stage N: Stage Title) and include the \
complete analytical content from that stage's output.

**Stage ordering and headings:**
- ## Stage 1: System Model
- ## Stage 2: Threat Identification
- ## Stage 3: Mitigations
- ## Stage 4: Validation

### Content Preservation Rules

When consolidating stage outputs, follow these rules strictly:

- **Preserve all Mermaid diagrams exactly as written.** Do not modify Mermaid syntax, \
node labels, edge labels, or diagram structure. Mermaid diagrams are executable code \
— any modification can break rendering.

- **Preserve all threat tables, STRIDE category matrices, and risk ratings.** Do not \
convert tables to prose or flatten structured data.

- **Preserve all code locations and file references.** Specific file paths and line \
numbers must be reproduced exactly.

- **Preserve all mitigation recommendations, effort estimates, and priority tiers \
(P0–P3).** Every item from Stage 3 must appear in the consolidated report.

- **Preserve all gap assessments, accepted risks, and review cadence recommendations \
from Stage 4.** Every validation finding must be included.

- **Preserve all CWE identifiers, CVE references, and external standard references.** \
These are precise cross-references — do not paraphrase or abbreviate them.

### Content Cleanup Rules

While preserving all technical content, clean up the following artifacts that may \
appear in stage outputs due to the AI agent's analytical process:

- **Remove conversational artifacts:** Phrases like "Let me analyze...", \
"I'll start by...", "Based on my review...", "Looking at the codebase...", or \
similar first-person process narration. The report should read as an authoritative \
document, not a conversation transcript.

- **Remove investigation process notes:** Phrases describing the agent's file \
navigation, tool usage, or analysis sequence. The report documents findings, not \
the process of finding them.

- **Normalize heading levels:** Ensure heading hierarchy is consistent throughout \
the document. Stage-level content should use ### and #### under each ## Stage heading. \
Resolve any heading level conflicts between stages.

- **Deduplicate cross-references:** Where multiple stages reference the same \
threat or finding, ensure consistent naming and cross-references. Do not \
remove the references — just ensure they use the same identifiers.

- **Fix formatting inconsistencies:** Normalize markdown formatting (bullet styles, \
code fence languages, emphasis patterns) to be consistent throughout the document.

## OUTPUT REQUIREMENTS

Write the consolidated report to `{output_dir}05-report.md`. Create the \
`{output_dir}` directory if it does not already exist.

Structure the report as follows:

1. **Title:** # Threat Model Report
2. **Executive Summary:** ## Executive Summary (as described above)
3. **Stage 1–4 content:** ## Stage N: Stage Title sections in order

The report must be a complete, standalone document. A reader holding only \
`05-report.md` should have access to every finding, diagram, threat scenario, \
mitigation recommendation, and validation assessment produced by the threat \
modeling process.

**Quality standards:**
- The executive summary must accurately reflect the findings — do not overstate or \
understate the risk posture
- Every technical artifact (diagrams, tables, identifiers, code references) must be \
preserved verbatim
- The document must read as a professional security assessment report, not as a \
collection of AI agent outputs
- Heading hierarchy must be clean and navigable
- Cross-references between stages should be consistent and traceable
"""


def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
    """Build the complete Stage 5 report consolidation prompt with prior stage outputs.

    Args:
        context: StageContext with optional prior_outputs containing
                 "stage_01_output" through "stage_04_output" markdown.
        output_dir: Output directory for deliverables (defaults to "threatmodel").
                   Accepts with or without trailing slash.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.prior_outputs.get("stage_01_output") or None
    stage_02_output = context.prior_outputs.get("stage_02_output") or None
    stage_03_output = context.prior_outputs.get("stage_03_output") or None
    stage_04_output = context.prior_outputs.get("stage_04_output") or None
    normalized_dir = output_dir.rstrip("/") + "/"

    # Build prior stages section
    if any([stage_01_output, stage_02_output, stage_03_output, stage_04_output]):
        parts = [
            "## PRIOR STAGE OUTPUTS\n",
            "The following outputs from all four 4QF+STRIDE stages are the complete "
            "analytical content you must consolidate. Every finding, diagram, threat "
            "scenario, and recommendation in these outputs must appear in your "
            "consolidated report. Do not add new analysis — your role is consolidation, "
            "formatting, and professional presentation only.\n",
            "<prior_stages>",
        ]

        if stage_01_output:
            parts.append("<stage_01_system_model>")
            parts.append(stage_01_output)
            parts.append("</stage_01_system_model>")

        if stage_02_output:
            parts.append("<stage_02_threat_identification>")
            parts.append(stage_02_output)
            parts.append("</stage_02_threat_identification>")

        if stage_03_output:
            parts.append("<stage_03_mitigations>")
            parts.append(stage_03_output)
            parts.append("</stage_03_mitigations>")

        if stage_04_output:
            parts.append("<stage_04_validation>")
            parts.append(stage_04_output)
            parts.append("</stage_04_validation>")

        parts.append("</prior_stages>")
        prior_stages_section = "\n".join(parts)
    else:
        prior_stages_section = ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    return prompt.replace("{output_dir}", normalized_dir)
