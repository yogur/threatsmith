# Stage 4 — Validation

**Four Question Framework question:** *Did we do a good job?*

This stage verifies the completeness and quality of the threat model produced in Stages 1–3, surfaces remaining gaps, documents accepted risks with justification, and recommends next steps and a review cadence. It must add value beyond restating prior stages — find genuine gaps.

**Deliverable:** write your analysis to `04-validation.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-system-model.md`, `02-threat-identification.md`, and `03-mitigations.md` from the output directory. Review each critically against the actual system.

## Mode framing

- **from-code** — Cross-reference the threat model against the actual codebase: walk the code for components, data flows, or entry points missing from the system model, and verify that mitigation recommendations point at real code locations.
- **from-docs** — Cross-reference against the design material instead: check that the model covers everything the design describes and that recommended controls are consistent with the intended architecture. Validate design completeness rather than code fidelity.
- **pair** — Review the assembled model with the human, confirming coverage decisions and capturing which gaps they accept versus commit to closing.

## Conditional reference guidance

When checking threat coverage, re-consult the OWASP references that applied to this system as completeness checklists: `references/owasp-web-top-10.md` (always), plus `references/owasp-api-top-10.md`, `references/owasp-llm-top-10.md`, or `references/owasp-mobile-top-10.md` for the surfaces this system has. Use them to verify Stage 2 didn't miss a category that applies.

## Analysis approach

### Component coverage verification

Verify the Stage 1 model captured the whole system: all significant components/services/subsystems, external dependencies and integrations, data stores with sensitivity classifications, entry points, and correctly-placed trust boundaries. Identify anything in the codebase (or design) not represented in the model.

### STRIDE category coverage verification

Verify Stage 2 applied each STRIDE category where relevant — Spoofing (authentication/identity points), Tampering (integrity for data stores, flows, configs), Repudiation (audit logging for security-relevant actions), Information Disclosure (sensitive data at rest, in transit, in logs), Denial of Service (availability for external-facing and shared resources), Elevation of Privilege (authorization boundaries and escalation paths). Identify component-category combinations that should have been analyzed but weren't.

### Mitigation completeness for high-priority threats

Verify Stage 3 adequately addressed the threats: do all P0/P1 threats have specific, actionable countermeasures; are proposed mitigations technically sound and implementable; are effort estimates realistic; are any threats marked mitigated but backed by weak/partial controls; are there mitigation dependencies that create bottlenecks.

### Remaining gaps

Document gaps found during validation: components missing from the model, STRIDE categories not applied where relevant, threats without adequate mitigation, mitigations that seem insufficient or mis-scoped, attack paths not considered, and environmental/deployment-specific risks not addressed.

### Accepted risks with justification

For each risk that cannot or should not be mitigated, document the risk description, the justification (cost-benefit, low likelihood, compensating controls, business decision), the conditions that should trigger re-evaluation, the compensating controls that reduce impact, and the risk owner accountable for monitoring it. No silent risk acceptance.

### Recommended next steps and review cadence

Provide immediate actions (critical gaps to close before the model is complete), short-term actions (next development cycle), review triggers (new features, architecture changes, incidents, dependency updates, regulatory changes), a recommended review cadence (quarterly / semi-annually / annually based on risk profile and rate of change), and any process improvements suggested by gaps found here.

## Output

Write `04-validation.md` with these sections:

1. **Validation Summary** — overall assessment: is the model sufficient, in need of minor improvement, or significantly gapped?
2. **Component Coverage Assessment** — results of cross-referencing the model against the system, listing missing components or data flows.
3. **STRIDE Coverage Assessment** — a matrix/table of which categories were applied to which components, highlighting gaps.
4. **Mitigation Adequacy Assessment** — evaluation of mitigation completeness for high-priority threats.
5. **Remaining Gaps** — consolidated, organized by severity.
6. **Accepted Risks** — with justification, re-evaluation conditions, and compensating controls.
7. **Recommended Next Steps** — prioritized actions and review cadence.

**Quality standards:**

- Every gap includes a specific remediation recommendation.
- Accepted risks have documented justification.
- Coverage assessments are evidence-based, referencing specific components and STRIDE categories.
- The validation identifies genuine gaps and improvements, not a restatement of prior stages.

This stage closes the Four Question Framework loop; Stage 5 consolidates all four stages into one executive deliverable.
