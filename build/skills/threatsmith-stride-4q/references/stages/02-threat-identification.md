# Stage 2 — Threat Identification

**Four Question Framework question:** *What can go wrong?*

This stage systematically identifies threats across every component, data flow, and trust boundary from the system model, using STRIDE as the completeness framework so no category of threat is overlooked for any component.

**Deliverable:** write your analysis to `02-threat-identification.md` in the output directory (default `threatmodel/`).

## Read the prior stage

Read `01-system-model.md` from the output directory first. Extract the complete inventory — components, entry points, actors, trust boundaries, data flows — and build a checklist of everything that must be covered. **Every component from Stage 1 must appear in at least one threat finding.**

## Mode framing

- **from-code** — Ground every threat in observed code: vulnerable patterns, missing validation, weak authorization. Cite specific files and lines. Also run available scanners (see below).
- **from-docs** — The code may not exist, so reason about threats inherent to the *design*: where the architecture creates exposure, which trust boundaries are crossed, which controls the design does or doesn't commit to. Frame findings as design-level risks and note where implementation choices will determine the outcome. Scanners generally don't apply when there's no code.
- **pair** — Walk the human through threats component by component, asking about controls you can't see ("is there authz on this endpoint?", "is this data encrypted at rest?") and recording answers as you go.

## Reference checklists

Apply the six STRIDE categories — detailed in the "Systematic STRIDE analysis" section below — to every component as your primary completeness framework. Alongside them, use these OWASP reference files (synced into `references/` alongside the stages) as structured coverage checklists:

- **Always:** `references/owasp-web-top-10.md` — map each item to identified threats or explicitly note why it's not applicable.
- **Conditionally** — consult these based on the system's nature as captured in the Stage 1 model:
  - `references/owasp-api-top-10.md` — **if the system exposes HTTP APIs** (REST, GraphQL, webhooks, service-to-service APIs).
  - `references/owasp-llm-top-10.md` — **if the system integrates an LLM or AI model** (prompt construction, model calls, agentic tools).
  - `references/owasp-mobile-top-10.md` — **if the system has a mobile client.**

You built the system model, so you decide which conditional references apply — pull in the ones that match and skip the ones that don't.

## Scanner integration (from-code)

In `from-code` mode, consult `references/scanners.md`: it lists the scanners to look for and how to run them. Detect which are available on the system, run the ones present, and map each finding to the relevant STRIDE category and affected component. Scanner results are automated *evidence* that complements manual analysis — they don't replace it.

## Systematic STRIDE analysis

Apply all six STRIDE categories to every major component, entry point, data flow, and trust boundary:

- **Spoofing** — Can an attacker impersonate a user, service, or component? Examine authentication, token/certificate validation, and identity federation. Consider both external and internal (compromised-service) spoofing.
- **Tampering** — Can data be modified undetected? Examine input validation at every trust-boundary crossing, write controls, file/message integrity, and data-in-transit protection. Follow each Stage 1 data flow and find where tampering is possible and where integrity checks exist or are missing.
- **Repudiation** — Can an actor deny an action? Examine logging coverage, audit-trail completeness, log integrity, and whether security-critical operations leave non-repudiable evidence.
- **Information Disclosure** — Can sensitive data leak? Examine error messages, debug output, API responses, logs, timing side channels, cache behavior, and backup/temp files. Cross-reference Stage 1's data classification — every confidential/restricted data item needs its disclosure paths analyzed.
- **Denial of Service** — Can availability be degraded? Examine resource consumption, rate limiting, connection pooling, queue depth, algorithmic complexity of input handling, and cascading-failure paths. Consider both volumetric and application-layer exhaustion.
- **Elevation of Privilege** — Can an attacker gain more access than authorized? Examine authorization enforcement, RBAC implementation, escalation paths through chained operations, default permissions, and admin-function access.

## Threat scenario construction

For each identified threat, construct a concrete scenario:

- **Attacker motivation** — why target this component; the value of the asset gained or compromised.
- **Attacker capability** — skill, tools, and access required. Characterize as opportunistic, motivated (skilled external), insider, or advanced (nation-state / organized crime).
- **Attack narrative** — entry point, exploitation method, lateral movement if relevant, and end goal, referencing specific code paths, configs, or architectural patterns.
- **Impact** — categorize by Confidentiality / Integrity / Availability and estimate severity (Critical / High / Medium / Low).

## Output

Write `02-threat-identification.md`, organized by component or by STRIDE category — whichever gives clearer coverage. For each threat document: title and STRIDE category(ies); affected component(s) and entry points (referencing Stage 1); attacker motivation and capability; attack narrative with specific references; relevant OWASP category if applicable; severity with rationale; and which of C/I/A are impacted.

**Quality standards:**

- Ground every threat in evidence (code in `from-code`, design in `from-docs`) — avoid generic threats unsupported by the system.
- Distinguish confirmed threats (observed vulnerable patterns) from potential threats (architectural risks needing further analysis).
- Be specific: *"the /api/users endpoint accepts user-supplied IDs without ownership validation in handlers/users.py:45"* beats *"the API might have authorization issues."*
- Ensure every Stage 1 component appears in at least one finding — partial coverage is not acceptable.

This threat inventory is the foundation for Stage 3, where every threat is mapped to countermeasures and assessed for residual risk.
