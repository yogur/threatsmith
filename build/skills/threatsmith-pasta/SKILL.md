---
name: threatsmith-pasta
description: Threat model a system using the PASTA methodology (Process for Attack Simulation and Threat Analysis) — a risk-centric, 7-stage process that ties threats to business impact, producing a structured set of markdown deliverables (objectives, technical scope, decomposition, threat analysis, vulnerability analysis, attack modeling, risk & impact) plus a consolidated report. Use this whenever someone wants a thorough, risk-driven threat model: simulating attacks, building attack trees, scoring vulnerabilities with CVSS, prioritizing remediation by business risk, or producing a board-ready security assessment — whether from existing code, from design docs for an unbuilt feature, or interactively alongside a human. Trigger it for requests like "run a PASTA threat model", "do a risk-centric threat assessment", "build attack trees for this service", or "prioritize our security risks by business impact", even if the user doesn't name PASTA explicitly. For a lighter-weight model, the 4QF+STRIDE skill is the faster default; reach for PASTA when depth and risk prioritization matter.
---

# ThreatSmith — PASTA Threat Modeling

PASTA (**Process for Attack Simulation and Threat Analysis**) is a risk-centric methodology that works from business objectives down to concrete, prioritized remediation. It runs in seven analytical stages, each building on the last:

1. **Define Objectives** (stage 01) — business context, data sensitivity, compliance.
2. **Define Technical Scope** (stage 02) — attack-surface boundary and technology landscape.
3. **Application Decomposition** (stage 03) — use cases, actors, entry points, assets, data flows, trust boundaries.
4. **Threat Analysis** (stage 04) — systematic threat identification (STRIDE + scenarios + intelligence).
5. **Vulnerability & Weakness Analysis** (stage 05) — concrete, scored vulnerabilities tied to threats.
6. **Attack Modeling** (stage 06) — attack trees and exploitation paths.
7. **Risk & Impact Analysis** (stage 07) — business-impact risk ratings and a prioritized remediation roadmap.

A final consolidation step (stage 08) assembles the seven analytical stages into one professional report.

Each stage is a self-contained document under `references/stages/`. You produce one markdown deliverable per stage into an output directory, and later stages read the earlier deliverables they need **from disk by path**. PASTA is cumulative — every stage leans heavily on the ones before it, so producing the stages in order matters more here than in lighter methodologies.

## Choosing a mode

Threat modeling happens at different points in the software lifecycle, and the right starting material differs at each. This skill supports three modes, each suited to a phase of the SDLC. **If the invoker did not supply a mode, ask which one fits before starting** — the right framing changes how every stage behaves:

| Mode | Where it fits in the lifecycle | How it works |
|------|--------------------------------|--------------|
| `from-code` | **After implementation** — the system (or feature) is already built, and you're modeling what exists. It can also fit design-phase work where existing code is paired with fresh docs describing a yet-to-be-built feature. | Analyze the actual code (and any docs present) in the working directory. Code is the primary source of truth; use docs to corroborate and fill in intent. |
| `from-docs` | **During design / requirements** — the system or feature is specified but **not yet implemented** (a planned feature, redesign, or greenfield project). | Build the model from design material rather than code. See "from-docs context discovery" below. |
| `pair` | **During design or early development**, collaborating live with a human while details are still forming. | Work through the stages interactively — ask clarifying questions, draft each stage doc, confirm it with the human, then advance. Best for greenfield or fast-moving work. |

When a mode **is** supplied (for example, the invoker says "from the design docs" or "pair with me"), honor it without re-asking.

PASTA leans on detail that may be thin or absent before code exists (CVSS scoring, dependency CVEs, line-level vulnerability evidence). In `from-docs` and `pair` modes, the early stages (objectives, scope, decomposition, threat analysis) translate cleanly; the later stages (vulnerability, attack modeling, risk) shift from confirming concrete findings to reasoning about the *designed* controls and the risks the design implies — see each stage's mode framing for how to adapt.

### from-docs context discovery

In `from-docs` mode the code may not exist yet, so **discover the context yourself rather than expecting fixed input paths**:

- Look through the working directory for design material — READMEs, `docs/`, specs, PRDs, RFCs, architecture notes, plan files. Read what's relevant.
- The invoker may also point you at **external** context: ticket IDs, Linear/Jira issues, Confluence pages, design-doc links. When they do and the matching MCP servers (e.g. `linear`, `confluence`, `jira`) are available, fetch that context directly before building the objectives and scope.
- Example invocation: *"model the auth redesign described in LINEAR-482 and the Confluence page linked there, using the linear and confluence MCP servers."* Gather that material first, then proceed.

There is no hardcoded input contract — the behavior is "discover what exists locally; fetch what the invoker points you to."

## Output directory

Unless the invoker specifies otherwise, write all deliverables to `threatmodel/`. Stage files refer to this as the output directory. Keep the filenames exactly as each stage specifies (`01-objectives.md` … `08-report.md`) — downstream tooling and the report stage rely on them.

## Running a full threat model (human walkthrough)

Work through the stages **in order**, within one session:

1. Confirm the mode (ask if not supplied) and the output directory.
2. For each stage in order, read its file under `references/stages/`, perform the work it describes, and write its deliverable to the output directory.
3. Before starting a stage that depends on earlier work, **re-read only the prior deliverable files that stage needs** from the output directory — this keeps your working context lean instead of carrying everything forward.
4. After stage 07, run stage 08 to consolidate everything into `08-report.md`.

## Running a single stage

Each stage is independently runnable. Given a stage to run, the mode, the output directory, and the location of prior outputs, open that stage's file and execute only it — reading whatever prior deliverables it needs from the output directory and writing only its own deliverable. A single-stage run must produce the same result it would as part of a full walkthrough.

A single stage may be run interactively by a person, or **non-interactively** by an orchestrator that supplies the stage, mode, output directory, and prior-output location up front. When the invocation is non-interactive — the caller signals it, or there is simply no human available to answer — run to completion without pausing for input: if something is ambiguous or a prior deliverable the stage expects is missing, proceed with the best-supported interpretation and record the assumption in the deliverable rather than stopping to ask. When run interactively, you may ask clarifying questions — following the mode's framing — but only where something material is genuinely unclear and the answer would change the analysis; don't ask for its own sake when the available context already suffices.

## Stages

| Stage | File | Deliverable |
|-------|------|-------------|
| 1 — Define Objectives | `references/stages/01-objectives.md` | `01-objectives.md` |
| 2 — Define Technical Scope | `references/stages/02-technical-scope.md` | `02-technical-scope.md` |
| 3 — Application Decomposition | `references/stages/03-application-decomposition.md` | `03-application-decomposition.md` |
| 4 — Threat Analysis | `references/stages/04-threat-analysis.md` | `04-threat-analysis.md` |
| 5 — Vulnerability & Weakness Analysis | `references/stages/05-vulnerability-analysis.md` | `05-vulnerability-analysis.md` |
| 6 — Attack Modeling | `references/stages/06-attack-modeling.md` | `06-attack-modeling.md` |
| 7 — Risk & Impact Analysis | `references/stages/07-risk-and-impact-analysis.md` | `07-risk-and-impact-analysis.md` |
| 8 — Report | `references/stages/08-report.md` | `08-report.md` |

## Reference material

Methodology reference files live alongside the stages under `references/`:

- `references/owasp-web-top-10.md` — web coverage checklist (always relevant in stage 04).
- `references/owasp-api-top-10.md`, `references/owasp-llm-top-10.md`, `references/owasp-mobile-top-10.md` — **conditional** checklists. Consult the API list if the system exposes HTTP APIs, the LLM list if it integrates an LLM/AI model, the Mobile list if it has a mobile client. The stage files tell you when each applies; you decide based on the scope and decomposition you built.
- `references/scanners.md` — how to detect and run available security scanners. Used in stage 05 in `from-code` mode.
