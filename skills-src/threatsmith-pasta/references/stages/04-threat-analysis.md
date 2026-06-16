# Stage 4 — Threat Analysis

This stage systematically identifies, documents, and contextualizes every plausible threat against the application by combining a structural framework (STRIDE), probabilistic scenario analysis, historical regression analysis, and threat-intelligence correlation. It transforms the Stage 3 decomposition into a comprehensive threat inventory that drives vulnerability analysis (Stage 5), attack modeling (Stage 6), and risk prioritization (Stage 7).

**Analyze ALL major components from the decomposition.** Every component, entry point, data flow, and trust boundary from Stage 3 must be examined for threats — partial analysis is not acceptable.

**Deliverable:** write your analysis to `04-threat-analysis.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-objectives.md`, `02-technical-scope.md`, and `03-application-decomposition.md` from the output directory. Use Stage 1's data classifications to assess impact, Stage 2's stack to identify technology-specific threat patterns, and the Stage 3 decomposition as your structural map — build a checklist of every component and entry point that must be covered.

## Mode framing

- **from-code** — Ground threats in observed code: vulnerable patterns, missing controls, weak authorization. Cite specific files and lines.
- **from-docs** — The code may not exist, so reason about threats inherent to the *design*: where the architecture creates exposure, which trust boundaries are crossed, which controls the design does or doesn't commit to. Frame findings as design-level risks and note where implementation will determine the outcome.
- **pair** — Walk the human through threats component by component, asking about controls you can't see and recording answers as you go.

## Reference checklists

Apply the six STRIDE categories — detailed in the "STRIDE threat analysis" pillar below — to every component as your structural completeness framework. Alongside them, use these OWASP reference files (synced into `references/` alongside the stages) as coverage-validation checklists in the "Threat intelligence correlation" pillar:

- **Always:** `references/owasp-web-top-10.md` — map each item to identified threats or explicitly note why it's not applicable.
- **Conditionally** — consult these based on the system's nature as recorded in the Stage 3 decomposition:
  - `references/owasp-api-top-10.md` — **if the system exposes HTTP APIs** (REST, GraphQL, webhooks, service-to-service APIs).
  - `references/owasp-llm-top-10.md` — **if the system integrates an LLM or AI model** (prompt construction, model calls, agentic tools).
  - `references/owasp-mobile-top-10.md` — **if the system has a mobile client.**

You built the decomposition, so you decide which conditional references apply — pull in the ones that match and skip the ones that don't.

## Analysis pillars

Address each of these four pillars (they become the top-level sections of your output):

### 1. STRIDE threat analysis

Apply all six STRIDE categories to every major component, entry point, and data flow from Stage 3. STRIDE is your structural completeness framework — it ensures no category of threat is overlooked for any component.

- **Spoofing** — Can an attacker impersonate a user, service, or component? Examine authentication, token/certificate validation, and identity federation. Consider external and internal (compromised-service) spoofing.
- **Tampering** — Can data be modified undetected? Examine input validation at every trust-boundary crossing, write controls, file/message integrity, and data-in-transit protection. Follow each Stage 3 data flow and find where tampering is possible and where integrity checks exist or are missing.
- **Repudiation** — Can an actor deny an action? Examine logging coverage, audit-trail completeness, log integrity, and whether security-critical operations leave non-repudiable evidence.
- **Information Disclosure** — Can sensitive data leak? Examine error messages, debug output, API responses, logs, timing side channels, cache behavior, and backup/temp files. Cross-reference Stage 1's data classification — every confidential/restricted data item needs its disclosure paths analyzed.
- **Denial of Service** — Can availability be degraded? Examine resource consumption, rate limiting, connection pooling, queue depth, algorithmic complexity of input handling, and cascading-failure paths. Consider volumetric and application-layer exhaustion.
- **Elevation of Privilege** — Can an attacker gain more access than authorized? Examine authorization enforcement, RBAC implementation, escalation paths through chained operations, default permissions, and admin-function access. Trace the Stage 3 actor trust levels and find where boundaries can be crossed.

Track component coverage as you go: if the application has N major components, your STRIDE analysis should address all N. Verify none are skipped before concluding.

### 2. Probabilistic attack scenario analysis

Construct realistic, end-to-end attack scenarios. For each: a **scenario narrative** (from the attacker's perspective — what they want, know, do, and achieve, with the specific entry point and exploit chain); **preconditions** (access, knowledge, system state required); a **probability assessment** (High / Medium / Low based on attacker motivation, attack complexity, precondition prevalence, and detection difficulty); **kill-chain mapping** for multi-step scenarios (initial access → execution → persistence → privilege escalation → lateral movement → exfiltration → impact, noting where each could be detected or interrupted); and **cross-component cascading** (how compromising one component enables attacks on others). Prioritize scenarios targeting the highest-value assets, exploiting Stage 3 trust-boundary crossings, chaining lower-severity weaknesses, and reflecting realistic attacker behavior (external and insider).

### 3. Regression analysis on security events

Ground the analysis in historical precedent: technology-specific threat history for each major stack component; architectural-pattern analysis (how similar architectures — microservices, monolith, serverless — have been attacked); component-level regression (known failure modes for auth, authorization, session management, crypto, file handling, input parsing); similar-incident patterns for the application's domain; and the dependency threat landscape (historical vulnerability classes for significant Stage 2 dependencies).

### 4. Threat intelligence correlation

Connect code-level analysis to the broader landscape: **OWASP cross-referencing** (map each threat to the relevant OWASP categories from the reference files; document categories with no findings as either gaps to investigate or explicitly not applicable); **public vulnerability pattern matching** (which CVE/CWE classes the stack is predisposed to — you are not running scanners here, that is Stage 5); **threat-actor profiling** (opportunistic, motivated external, insider, advanced — for each relevant class, what they target, what techniques they use, which entry points they exploit); **supply-chain threat assessment** (relevant attack vectors and single points of compromise); and **emerging threat patterns** relevant to the stack.

## Investigation approach

- **Context integration and planning** — review all prior outputs; extract the component inventory, entry points, actors, trust boundaries, and data flows; build a coverage checklist.
- **Systematic threat identification** — apply STRIDE to each component; construct probabilistic scenarios for the highest-risk areas; perform regression analysis; correlate with OWASP checklists.
- **Cross-cutting analysis and validation** — identify threats emerging from component interactions; validate component and OWASP coverage; consolidate duplicate or overlapping threats.

## Output

Write `04-threat-analysis.md` with the four pillar headings as top-level sections (## STRIDE Threat Analysis, ## Probabilistic Attack Scenario Analysis, ## Regression Analysis on Security Events, ## Threat Intelligence Correlation). For each identified threat document: description and exploitation mechanism; affected component(s) and entry points (referencing Stage 3); STRIDE category(ies); relevant OWASP category if applicable; probability (High/Medium/Low) with rationale; potential impact (which of C/I/A); prerequisites; and codebase evidence (specific file paths/configs/patterns, or design references in `from-docs` mode).

**Completeness requirements:**

- Every major Stage 3 component appears in at least one threat finding; every trust-boundary crossing is analyzed.
- Every relevant OWASP category maps to at least one finding; categories that don't apply are explicitly noted.
- Scenarios cover both the most likely and the most impactful threats.

**Quality standards:**

- Ground threats in evidence (code in `from-code`, design in `from-docs`) — avoid generic threats unsupported by the system.
- Distinguish confirmed threats (observed vulnerable patterns) from potential threats (architectural risks needing Stage 5 analysis).
- Be specific: *"the /api/users endpoint accepts user-supplied IDs without ownership validation in handlers/users.py:45"* beats *"the API might have authorization issues."*
- Cross-reference findings across pillars — a STRIDE finding should connect to its scenario, regression context, and OWASP mapping.

Your threat inventory is the foundation for everything that follows: Stage 5 validates each threat against the code, Stage 6 models attacks along these scenarios, Stage 7 prioritizes by your probability and impact assessments.
