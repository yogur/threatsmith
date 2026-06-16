---
name: threatsmith-stride-4q
description: Threat model a system using the Four Question Framework + STRIDE methodology, producing a structured set of markdown deliverables (system model, threat identification, mitigations, validation, and a consolidated report). Use this whenever someone wants to threat model an application, analyze a system's attack surface, identify STRIDE threats, plan security mitigations, or produce a security/threat assessment — whether from existing code, from design docs for an unbuilt feature, or interactively alongside a human. Trigger it for requests like "threat model this service", "what can go wrong with this design", "do a STRIDE analysis", or "assess the security risks of this change", even if the user doesn't name STRIDE or threat modeling explicitly.
---

# ThreatSmith — 4QF + STRIDE Threat Modeling

This skill walks a system through the **Four Question Framework (4QF)** structured around **STRIDE**:

1. **What are we working on?** → System Model (stage 01)
2. **What can go wrong?** → Threat Identification (stage 02)
3. **What are we going to do about it?** → Mitigations (stage 03)
4. **Did we do a good job?** → Validation (stage 04)

A final consolidation step (stage 05) assembles the four analytical stages into one professional report.

Each stage is a self-contained document under `references/stages/`. You produce one markdown deliverable per stage into an output directory, and later stages read the earlier deliverables they need **from disk by path**.

## Choosing a mode

Threat modeling happens at different points in the software lifecycle, and the right starting material differs at each. This skill supports three modes, each suited to a phase of the SDLC. **If the invoker did not supply a mode, ask which one fits before starting** — the right framing changes how every stage behaves:

| Mode | Where it fits in the lifecycle | How it works |
|------|--------------------------------|--------------|
| `from-code` | **After implementation** — the system (or feature) is already built, and you're modeling what exists. It can also fit design-phase work where existing code is paired with fresh docs describing a yet-to-be-built feature. | Analyze the actual code (and any docs present) in the working directory. Code is the primary source of truth; use docs to corroborate and fill in intent. |
| `from-docs` | **During design / requirements** — the system or feature is specified but **not yet implemented** (a planned feature, redesign, or greenfield project). | Build the model from design material rather than code. See "from-docs context discovery" below. |
| `pair` | **During design or early development**, collaborating live with a human while details are still forming. | Work through the stages interactively — ask clarifying questions, draft each stage doc, confirm it with the human, then advance. Best for greenfield or fast-moving work. |

When a mode **is** supplied (for example, the invoker says "from the design docs" or "pair with me"), honor it without re-asking.

### from-docs context discovery

In `from-docs` mode the code may not exist yet, so **discover the context yourself rather than expecting fixed input paths**:

- Look through the working directory for design material — READMEs, `docs/`, specs, PRDs, RFCs, architecture notes, plan files. Read what's relevant.
- The invoker may also point you at **external** context: ticket IDs, Linear/Jira issues, Confluence pages, design-doc links. When they do and the matching MCP servers (e.g. `linear`, `confluence`, `jira`) are available, fetch that context directly before building the system model.
- Example invocation: *"model the auth redesign described in LINEAR-482 and the Confluence page linked there, using the linear and confluence MCP servers."* Gather that material first, then proceed.

There is no hardcoded input contract — the behavior is "discover what exists locally; fetch what the invoker points you to."

## Output directory

Unless the invoker specifies otherwise, write all deliverables to `threatmodel/`. Stage files refer to this as the output directory. Keep the filenames exactly as each stage specifies (`01-system-model.md` … `05-report.md`) — downstream tooling and the report stage rely on them.

## Running a full threat model (human walkthrough)

Work through the stages **in order**, within one session:

1. Confirm the mode (ask if not supplied) and the output directory.
2. For each stage in order, read its file under `references/stages/`, perform the work it describes, and write its deliverable to the output directory.
3. Before starting a stage that depends on earlier work, **re-read only the prior deliverable files that stage needs** from the output directory — this keeps your working context lean instead of carrying everything forward.
4. After stage 04, run stage 05 to consolidate everything into `05-report.md`.

## Running a single stage

Each stage is independently runnable. Given a stage to run, the mode, the output directory, and the location of prior outputs, open that stage's file and execute only it — reading whatever prior deliverables it needs from the output directory and writing only its own deliverable. A single-stage run must produce the same result it would as part of a full walkthrough.

## Stages

| Stage | File | Deliverable |
|-------|------|-------------|
| 1 — System Model | `references/stages/01-system-model.md` | `01-system-model.md` |
| 2 — Threat Identification | `references/stages/02-threat-identification.md` | `02-threat-identification.md` |
| 3 — Mitigations | `references/stages/03-mitigations.md` | `03-mitigations.md` |
| 4 — Validation | `references/stages/04-validation.md` | `04-validation.md` |
| 5 — Report | `references/stages/05-report.md` | `05-report.md` |

## Reference material

Methodology reference files live alongside the stages under `references/`:

- `references/owasp-web-top-10.md` — web coverage checklist (always relevant in stage 02).
- `references/owasp-api-top-10.md`, `references/owasp-llm-top-10.md`, `references/owasp-mobile-top-10.md` — **conditional** checklists. Consult the API list if the system exposes HTTP APIs, the LLM list if it integrates an LLM/AI model, the Mobile list if it has a mobile client. The stage files tell you when each applies; you decide based on the system model you built.
- `references/scanners.md` — how to detect and run available security scanners. Used in stage 02 in `from-code` mode.
