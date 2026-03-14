"""Stage 8 — Report Consolidation prompt template (post-pipeline step)."""

STAGE_PROMPT = """\
You are a technical report editor performing the final consolidation step of a \
PASTA (Process for Attack Simulation and Threat Analysis) threat model. Your task \
is to consolidate the outputs from all seven analytical stages into a single, \
cohesive, professionally formatted deliverable. This is NOT a PASTA stage — it is \
a deliverable generation step. You must NOT perform any new analysis, generate new \
findings, or introduce information that does not appear in the stage outputs.

**CRITICAL REQUIREMENT: You must preserve ALL technical content from every stage. \
Every vulnerability, every CVSS score, every Mermaid diagram, every attack tree, \
every countermeasure, every remediation item, and every risk rating from Stages 1-7 \
must appear in the consolidated report. Omitting or summarizing away technical \
detail is unacceptable.**

{prior_stages_section}

## CONSOLIDATION INSTRUCTIONS

Your consolidation must produce a single markdown document that serves as the \
definitive threat model deliverable. The document must be self-contained — a reader \
should not need to consult individual stage files to understand the findings.

### Executive Summary

Open the report with an executive summary that distills the most critical findings \
across all seven stages into a concise overview for stakeholders who may not read \
the full report. The executive summary must include:

- **Scope:** What was analyzed (application name, technology stack, boundaries) — \
drawn from Stages 1 and 2
- **Critical findings count:** How many Critical, High, Medium, and Low risk items \
were identified — drawn from Stage 7's risk ratings
- **Top risks:** The 3-5 highest-priority risks with one-sentence descriptions — \
drawn from Stage 7's remediation roadmap P0/P1 items
- **Key recommendations:** The most impactful countermeasures — drawn from Stage 7's \
cost-effectiveness analysis (quick wins and strategic investments)
- **Overall risk posture:** A one-paragraph assessment of the application's security \
posture based on the aggregate findings

The executive summary must be factual and grounded in the stage outputs. Do not \
editorialize or add qualitative assessments that are not supported by the analysis.

### Stage Content Consolidation

Following the executive summary, include the full content from each stage in order. \
For each stage, use a top-level heading (## Stage N: Stage Title) and include the \
complete analytical content from that stage's output.

**Stage ordering and headings:**
- ## Stage 1: Define Objectives
- ## Stage 2: Define Technical Scope
- ## Stage 3: Application Decomposition
- ## Stage 4: Threat Analysis
- ## Stage 5: Vulnerability and Weakness Analysis
- ## Stage 6: Attack Modeling
- ## Stage 7: Risk and Impact Analysis

### Content Preservation Rules

When consolidating stage outputs, follow these rules strictly:

- **Preserve all Mermaid diagrams exactly as written.** Do not modify Mermaid syntax, \
node labels, edge labels, or diagram structure. Mermaid diagrams are executable code \
— any modification can break rendering.

- **Preserve all CVSS scores, vectors, and severity ratings.** Do not round, \
approximate, or recalculate any scores. Reproduce them verbatim.

- **Preserve all CWE identifiers, CVE references, and MITRE ATT&CK technique IDs.** \
These are precise cross-references — do not paraphrase or abbreviate them.

- **Preserve all code locations and file references.** Specific file paths and line \
numbers (e.g., api/users.py:34) must be reproduced exactly.

- **Preserve all tables, priority tiers (P0-P3), risk matrices, and structured \
data.** Do not convert tables to prose or flatten structured data.

- **Preserve all countermeasures, remediation items, and acceptance criteria.** \
Every item from the Stage 7 remediation roadmap must appear in the consolidated report.

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
vulnerability or finding, ensure consistent naming and cross-references. Do not \
remove the references — just ensure they use the same identifiers.

- **Fix formatting inconsistencies:** Normalize markdown formatting (bullet styles, \
code fence languages, emphasis patterns) to be consistent throughout the document.

## OUTPUT REQUIREMENTS

Write the consolidated report to `threatmodel/08-report.md`. Create the \
`threatmodel/` directory if it does not already exist.

Structure the report as follows:

1. **Title:** # Threat Model Report
2. **Executive Summary:** ## Executive Summary (as described above)
3. **Stage 1-7 content:** ## Stage N: Stage Title sections in order

The report must be a complete, standalone document. A reader holding only \
`08-report.md` should have access to every finding, diagram, score, \
recommendation, and remediation item produced by the threat modeling process.

**Quality standards:**
- The executive summary must accurately reflect the findings — do not overstate or \
understate the risk posture
- Every technical artifact (diagrams, scores, identifiers, code references) must be \
preserved verbatim
- The document must read as a professional security assessment report, not as a \
collection of AI agent outputs
- Heading hierarchy must be clean and navigable
- Cross-references between stages should be consistent and traceable
"""


def build_prompt(context: dict) -> str:
    """Build the complete Stage 8 prompt with prior stage injection.

    Args:
        context: Dict that may contain:
            - 'stage_01_output' through 'stage_07_output': raw markdown from prior stages

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.get("stage_01_output") or None
    stage_02_output = context.get("stage_02_output") or None
    stage_03_output = context.get("stage_03_output") or None
    stage_04_output = context.get("stage_04_output") or None
    stage_05_output = context.get("stage_05_output") or None
    stage_06_output = context.get("stage_06_output") or None
    stage_07_output = context.get("stage_07_output") or None

    # Build prior stages section
    if any(
        [
            stage_01_output,
            stage_02_output,
            stage_03_output,
            stage_04_output,
            stage_05_output,
            stage_06_output,
            stage_07_output,
        ]
    ):
        parts = [
            "## PRIOR STAGE OUTPUTS\n",
            "The following outputs from all seven PASTA stages are the complete "
            "analytical content you must consolidate. Every finding, diagram, score, "
            "and recommendation in these outputs must appear in your consolidated "
            "report. Do not add new analysis — your role is consolidation, formatting, "
            "and professional presentation only.\n",
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

        if stage_07_output:
            parts.append("<stage_07_risk_impact>")
            parts.append(stage_07_output)
            parts.append("</stage_07_risk_impact>")

        parts.append("</prior_stages>")
        prior_stages_section = "\n".join(parts)
    else:
        prior_stages_section = ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    return prompt
