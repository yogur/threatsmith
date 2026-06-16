# Stage 5 — Report Consolidation

This is the final consolidation step. You act as a **technical report editor**, assembling the four analytical stages into one cohesive, professionally formatted deliverable. **This is not an analysis stage — do not perform new analysis, generate new findings, or introduce information that doesn't appear in the stage outputs.** For that reason it has no conditional reference guidance: you consult no OWASP/STRIDE checklists here, because you add no new threat content — you only consolidate what Stages 1–4 already produced.

**Deliverable:** write the consolidated report to `05-report.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-system-model.md`, `02-threat-identification.md`, `03-mitigations.md`, and `04-validation.md` from the output directory. These four files are the complete content you consolidate.

> **Preserve all technical content from every stage.** Every threat scenario, Mermaid diagram, mitigation recommendation, risk rating, gap assessment, and accepted risk from Stages 1–4 must appear in the consolidated report. Omitting or summarizing away technical detail defeats the purpose of the report.

The mode (`from-code` / `from-docs` / `pair`) doesn't change this stage — consolidation is identical regardless of how the underlying stages were produced.

## Consolidation instructions

Produce a single, self-contained markdown document — a reader holding only `05-report.md` should not need the individual stage files.

### Executive summary

Open with an executive summary that distills the most critical findings for stakeholders who won't read the full report. Include:

- **Scope** — what was analyzed (application name, technology stack, boundaries), from Stage 1.
- **Critical findings count** — threats identified, broken down by STRIDE category and priority, from Stage 2.
- **Top risks** — the 3–5 highest-priority threats with one-sentence descriptions, from Stage 2's scenarios.
- **Key mitigations** — the most impactful countermeasures, from Stage 3.
- **Validation outcome** — overall completeness assessment, from Stage 4.
- **Overall risk posture** — a one-paragraph assessment grounded in the aggregate findings.

Keep the summary factual and grounded in the stage outputs — don't editorialize or add assessments the analysis doesn't support.

### Stage content consolidation

After the executive summary, include the full content of each stage in order, under these headings:

- `## Stage 1: System Model`
- `## Stage 2: Threat Identification`
- `## Stage 3: Mitigations`
- `## Stage 4: Validation`

### Content preservation rules

- **Preserve all Mermaid diagrams exactly** — node labels, edge labels, and structure. Mermaid is executable; any change can break rendering.
- **Preserve all threat tables, STRIDE matrices, and risk ratings** — don't convert tables to prose or flatten structured data.
- **Preserve all code locations and file references** exactly.
- **Preserve all mitigation recommendations, effort estimates, and priority tiers (P0–P3).**
- **Preserve all gap assessments, accepted risks, and review-cadence recommendations from Stage 4.**
- **Preserve all CWE/CVE identifiers and external standard references** verbatim — don't paraphrase or abbreviate.

### Content cleanup rules

While preserving technical content, clean up process artifacts:

- **Remove conversational artifacts** — "Let me analyze…", "I'll start by…", "Based on my review…", first-person process narration. The report should read as an authoritative document, not a transcript.
- **Remove investigation process notes** — file-navigation, tool-usage, or analysis-sequence narration. Document findings, not the act of finding them.
- **Normalize heading levels** — stage content uses `###`/`####` under each `## Stage` heading; resolve conflicts between stages.
- **Deduplicate cross-references** — where stages reference the same threat, use consistent identifiers; don't drop the references.
- **Fix formatting inconsistencies** — normalize bullet styles, code-fence languages, and emphasis.

## Output

Write `05-report.md` structured as:

1. `# Threat Model Report`
2. `## Executive Summary`
3. `## Stage N: …` sections in order.

**Quality standards:**

- The executive summary accurately reflects the findings — neither overstates nor understates the risk posture.
- Every technical artifact (diagrams, tables, identifiers, code references) is preserved verbatim.
- The document reads as a professional security assessment, not a collection of agent outputs.
- Heading hierarchy is clean and navigable; cross-references are consistent and traceable.
