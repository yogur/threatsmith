# Stage 8 — Report Consolidation

This is the final consolidation step. You act as a **technical report editor**, assembling the seven analytical stages into one cohesive, professionally formatted deliverable. **This is not a PASTA stage — do not perform new analysis, generate new findings, or introduce information that doesn't appear in the stage outputs.** For that reason it has no conditional reference guidance: you consult no OWASP/scanner references here, because you add no new content — you only consolidate what Stages 1–7 already produced.

**Deliverable:** write the consolidated report to `08-report.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-objectives.md` through `07-risk-and-impact-analysis.md` from the output directory. These seven files are the complete content you consolidate.

> **Preserve all technical content from every stage.** Every vulnerability, CVSS score, Mermaid diagram, attack tree, countermeasure, remediation item, and risk rating from Stages 1–7 must appear in the consolidated report. Omitting or summarizing away technical detail defeats the purpose of the report.

The mode (`from-code` / `from-docs` / `pair`) doesn't change this stage — consolidation is identical regardless of how the underlying stages were produced.

## Consolidation instructions

Produce a single, self-contained markdown document — a reader holding only `08-report.md` should not need the individual stage files.

### Executive summary

Open with an executive summary that distills the most critical findings for stakeholders who won't read the full report. Include:

- **Scope** — what was analyzed (application name, technology stack, boundaries), from Stages 1 and 2.
- **Critical findings count** — how many Critical / High / Medium / Low risk items, from Stage 7's risk ratings.
- **Top risks** — the 3–5 highest-priority risks with one-sentence descriptions, from Stage 7's P0/P1 roadmap items.
- **Key recommendations** — the most impactful countermeasures, from Stage 7's cost-effectiveness analysis (quick wins and strategic investments).
- **Overall risk posture** — a one-paragraph assessment grounded in the aggregate findings.

Keep the summary factual and grounded in the stage outputs — don't editorialize or add assessments the analysis doesn't support.

### Stage content consolidation

After the executive summary, include the full content of each stage in order, under these headings:

- `## Stage 1: Define Objectives`
- `## Stage 2: Define Technical Scope`
- `## Stage 3: Application Decomposition`
- `## Stage 4: Threat Analysis`
- `## Stage 5: Vulnerability and Weakness Analysis`
- `## Stage 6: Attack Modeling`
- `## Stage 7: Risk and Impact Analysis`

### Content preservation rules

- **Preserve all Mermaid diagrams exactly** — node labels, edge labels, and structure. Mermaid is executable; any change can break rendering.
- **Preserve all CVSS scores, vectors, and severity ratings** — don't round, approximate, or recalculate. Reproduce verbatim.
- **Preserve all CWE identifiers, CVE references, and MITRE ATT&CK technique IDs** — precise cross-references; don't paraphrase or abbreviate.
- **Preserve all code locations and file references** (e.g. `api/users.py:34`) exactly.
- **Preserve all tables, priority tiers (P0–P3), risk matrices, and structured data** — don't convert tables to prose or flatten structured data.
- **Preserve all countermeasures, remediation items, and acceptance criteria** — every Stage 7 roadmap item must appear.

### Content cleanup rules

While preserving technical content, clean up process artifacts:

- **Remove conversational artifacts** — "Let me analyze…", "I'll start by…", "Based on my review…", first-person process narration. The report should read as an authoritative document, not a transcript.
- **Remove investigation process notes** — file-navigation, tool-usage, or analysis-sequence narration. Document findings, not the act of finding them.
- **Normalize heading levels** — stage content uses `###`/`####` under each `## Stage` heading; resolve conflicts between stages.
- **Deduplicate cross-references** — where stages reference the same vulnerability or finding, use consistent identifiers; don't drop the references.
- **Fix formatting inconsistencies** — normalize bullet styles, code-fence languages, and emphasis.

## Output

Write `08-report.md` structured as:

1. `# Threat Model Report`
2. `## Executive Summary`
3. `## Stage N: …` sections in order.

**Quality standards:**

- The executive summary accurately reflects the findings — neither overstates nor understates the risk posture.
- Every technical artifact (diagrams, scores, identifiers, code references) is preserved verbatim.
- The document reads as a professional security assessment, not a collection of agent outputs.
- Heading hierarchy is clean and navigable; cross-references are consistent and traceable.
