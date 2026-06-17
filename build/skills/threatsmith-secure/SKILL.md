---
name: threatsmith-secure
description: Apply an existing threat model to engineering work via two modes — `plan` and `review`. In `plan` mode it reads the threat model and produces a security augmentation layer (threat-informed requirements, constraints, and a checklist) for a change being designed or scoped, without owning or editing the planning document, so it composes with planning skills. In `review` mode it reads the threat model and audits a diff/PR/working changes, reporting uncatalogued threats the change introduces, required mitigations it fails to apply, and existing controls it weakens. Use this skill whenever a threat model (or any security/threat-assessment markdown) exists for the system and the user is about to plan, design, or scope a change ("help me plan the new payment flow", "what should I keep in mind building this endpoint"), OR is reviewing changes for security ("review this PR for security", "does this change introduce any threats", "did I miss any mitigations"). Trigger it even when the user doesn't say "threat model" — if one exists in the repo and the work touches security-relevant code (auth, data handling, network boundaries, input handling, secrets, third-party integrations), this skill keeps the catalogued threats and required controls in context so the work stays aligned with them. It is source-agnostic: it works on any directory of threat-model markdown, including hand-authored ones, and requires neither ThreatSmith-specific filenames nor metadata.json.
---

# ThreatSmith — Secure Coding from an Existing Threat Model

A threat model is only worth the effort if it actually shapes the code that gets written. This skill closes that loop: it reads an existing threat model and applies it at the two moments where it changes outcomes — when you're **planning** a change, and when you're **reviewing** one. In both, the goal is the same: keep the catalogued threats, trust boundaries, required mitigations, and accepted risks in context so the change you ship stays aligned with the security thinking that was already done.

## Choosing a mode

This skill has two modes. **If the invoker did not say which one they want, ask before starting** — they do quite different things:

| Mode | When it fits | What it produces |
|------|--------------|------------------|
| `plan` | *Before* writing code — you're planning, designing, or scoping a change and want it to respect the existing threat model from the start. | A **security augmentation layer**: threat-informed requirements, constraints, and a checklist that you (or a planning skill) fold into the plan. It never edits the plan itself. |
| `review` | *After* writing code — you have a diff, PR, or working changes and want to know whether they honor the threat model. | A **review report**: which catalogued threats and required mitigations the change touches, plus any threats it introduces that the model doesn't cover, and any required control it skips or weakens. |

Often a single phrase tells you which mode applies — "help me plan…" / "what should I watch out for building…" is `plan`; "review this PR" / "did this change miss anything" is `review`. Honor a clearly-implied mode without re-asking.

## Finding the threat model (source-agnostic)

Both modes read an **existing** threat model. This skill binds only to "readable threat-model markdown in a directory" — nothing more:

- **Locate the directory.** Use the path the invoker gives you. If none is given, look for an obvious one (`threatmodel/` is the common default; also check `docs/threat-model/`, `security/`, or wherever the repo keeps security docs). If you genuinely can't find one, say so and ask — don't invent threats from scratch, because the whole point is to apply work that already exists.
- **Read all the markdown in it.** Do not depend on specific filenames, a fixed number of files, a particular stage layout, or section headings. A ThreatSmith-generated model and a hand-authored one-file model must both work. Read what's there and extract the substance.
- **Extract the substance, not the format.** From whatever you find, pull out: the **threats** (what can go wrong, and to which component/data flow), the **trust boundaries** and assets, the **mitigations / required controls** (and their priority, e.g. P0–P3, if present), and any **accepted or residual risks**. These concepts appear in essentially every threat model even when the wording and structure differ.
- **`metadata.json` is optional.** If a `metadata.json` is present alongside the model you *may* use it opportunistically — for example, a commit hash that predates the change under review is a useful **staleness** hint worth flagging. But never require it: the skill must work fully on a directory that has none.

## `plan` mode

**Input:** a description of the change being planned (and an in-progress plan, PRD, design doc, or spec if one exists). **Goal:** produce a security augmentation layer that makes the eventual implementation honor the threat model.

1. **Understand the change.** From the change description and any planning artifact, work out which parts of the system it touches — which components, data flows, trust boundaries, and assets from the model are in play.
2. **Select the relevant threat-model content.** Pull the threats whose components/flows the change touches, the mitigations and required controls tied to those threats, and any accepted risks the change might disturb. Ignore the parts of the model the change doesn't touch — relevance keeps the output usable.
3. **Emit the augmentation layer.** Produce threat-informed, change-specific guidance the planner can act on, organized as:
   - **Security requirements** — what the change must do to satisfy the relevant mitigations/controls (e.g. "all new endpoints under `/admin` must enforce the existing role check — threat T-04").
   - **Constraints** — boundaries the change must not cross (e.g. "do not let the new export path bypass the data-classification filter at trust boundary B-02").
   - **Security checklist** — concrete, verifiable items to confirm before the change is considered done, each traceable to a threat or control in the model.
   Tie each item back to the specific threat/mitigation it comes from, so the reasoning is auditable and a reviewer can later check it.
4. **Note new exposure.** If the change plainly introduces a surface the threat model doesn't cover yet (a new external integration, a new data store, a new trust boundary), call it out as a gap for the threat model to catch up on — don't silently fold it in as if it were already analyzed.

**Composability — do not own the plan.** The augmentation layer is *additive*. Do **not** rewrite, reorganize, or take ownership of the planning document — the user may be driving it with a separate planning skill or by hand, and this skill has to compose with that in the same session. Deliver the layer as its own thing: write it to a clearly-named separate file (e.g. `security-augmentation.md`) or present it inline for the user/planning skill to fold in. Leave the decision of how to merge it to them.

## `review` mode

**Input:** a diff, PR, or set of working changes. **Goal:** tell the engineer whether the change stays aligned with the threat model.

1. **Get the change set.** Use the diff/PR the invoker points at, or inspect the working changes (e.g. `git diff`). Understand what the change actually does, not just which files it touches.
2. **Map the change onto the model.** Determine which catalogued threats, trust boundaries, and required mitigations the change is relevant to — the components and data flows it adds, removes, or alters.
3. **Report against three questions:**
   - **Uncatalogued threats** — does the change introduce a threat the model doesn't cover (a new entry point, a new data flow across a boundary, a new dependency, broadened privileges)? Flag each as a candidate addition to the threat model.
   - **Missing required mitigations** — for the threats the change touches, does it apply the controls the model requires? Flag any required mitigation (especially high-priority ones, e.g. P0/P1) that the change should implement but doesn't.
   - **Weakened controls** — does the change remove, bypass, or degrade an existing control the model relies on (disabling a check, widening access, dropping validation, loosening a boundary)? Flag each, naming the threat the control was protecting against.
4. **Be specific and grounded.** Tie every finding to a concrete location in the diff (file/line/hunk) *and* to the threat or mitigation in the model it relates to. A finding the engineer can't trace to both the code and the model is hard to act on.
5. **Staleness (optional).** If a `metadata.json` is present and records a commit hash older than the change under review, add a short note that the threat model may predate recent work and could itself need refreshing — as a hint, never as a blocker.

**Output:** a review report with a short summary line (e.g. "2 missing P0 mitigations, 1 uncatalogued threat, 0 weakened controls") followed by the findings grouped under **Uncatalogued threats**, **Missing mitigations**, and **Weakened controls**. If a group is empty, say so explicitly — "no weakened controls found" is a useful result, not an omission. If the change is clean against the model, say that plainly rather than manufacturing findings.

## Both modes

- **Apply what exists; don't re-model.** This skill consumes a threat model — it does not produce one. If the model is missing or far too thin to be useful, say so and suggest running a threat-modeling skill first, rather than inventing an analysis the user didn't ask for here.
- **Relevance over completeness.** In both modes, the value is in surfacing the parts of the model that bear on *this* change. Dumping the entire model back at the user buries the signal.
