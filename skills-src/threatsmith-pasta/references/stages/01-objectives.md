# Stage 1 — Define Objectives

This is the foundation of the entire PASTA process. Every later stage is evaluated through the business lens you establish here — what the application is for, what data it handles, and what an incident would cost. Thoroughness and accuracy matter: a gap here propagates through all seven stages.

**Deliverable:** write your analysis to `01-objectives.md` in the output directory (default `threatmodel/`).

## Mode framing

- **from-code** — Derive the business context from the repository (and any docs present): README, docs, configuration, data models, and the code itself. Code and config are the primary source of truth; docs corroborate intent.
- **from-docs** — The system may not be built yet. Build the objectives from design material — discover what exists locally (README, `docs/`, specs, PRDs, RFCs, plan files) and read it; if the invoker pointed you at external context (tickets, Confluence/Linear links) and the matching MCP servers are available, fetch that first. State the intended business purpose and data handling the design commits to.
- **pair** — Draft the objectives from available material, then ask the human about business goals, users, regulatory exposure, and the sensitivity of the data involved. Confirm before advancing.

## Analysis pillars

Address each of these four pillars (they become the top-level sections of your output):

### 1. Business objectives

What the application does and why it exists: the business problem it solves; intended users, customers, and stakeholders; business domain and industry context; key business functions, workflows, and processes; the value proposition and strategic goals; and the critical business processes that depend on it.

### 2. Security, compliance, and legal requirements

The guidelines, obligations, and constraints that govern the application: regulatory frameworks that apply given the data and industry (GDPR, HIPAA, PCI-DSS, SOX, FERPA, CCPA, etc.); licensing requirements and compatibility for third-party components; privacy and data-protection requirements; industry security standards (NIST, ISO 27001, SOC 2); legal obligations around data residency, retention, breach notification, and cross-border transfer; and contractual security requirements (customer SLAs, vendor agreements).

### 3. Business impact analysis

The potential impact of security incidents, including a thorough data-sensitivity analysis.

**Mission and process impact:** impact to mission and business processes if the application is compromised, degraded, or unavailable; which functions are most critical and least tolerant of disruption; recovery and business-continuity requirements; budget and financial impact of incidents; and system-resource and infrastructure dependencies.

**Data sensitivity classification:** inventory and classify all data the application handles, stores, or processes — PII (names, emails, addresses, phone numbers, government IDs, dates of birth, biometrics); financial data (payment cards, bank details, transaction records, billing); health data (medical records, insurance, treatment history); credentials and secrets (passwords, API keys, tokens, certificates, encryption keys, connection strings); proprietary information (trade secrets, IP, strategic plans); and other sensitive data (behavioral, location, communications). For each category, assess the classification level (public / internal / confidential / restricted), sources and destinations, retention and processing implications, and regulatory implications.

### 4. Operational impact

How the application affects operational processes and personnel: impact to existing operational processes; changes to logging, monitoring, or alerting that affect how teams interpret events; changes to deployment/maintenance/troubleshooting procedures; added steps for future changes; dependencies on operational infrastructure (CI/CD, monitoring, deployment platforms); training/knowledge requirements; and effects on incident response.

If the invoker supplied business or security objectives, use them as reference points to guide and validate your analysis — but still investigate independently and note any discrepancies between the stated objectives and what you find.

## Investigation approach

- **Documentation analysis** — READMEs, docs directories, API docs (OpenAPI/Swagger), config files that reveal business logic, package/project metadata, license and compliance docs, deployment/infra docs, changelogs.
- **Data-layer investigation** — database schemas and migrations, model/entity definitions, data-access code, validation/sanitization logic, field names indicating sensitive data (password, ssn, credit_card, token, secret, email, phone, address), env-var and config schemas.
- **Business-logic exploration** — entry points and routing, core service/controller logic, business rules and workflows, external integrations, authentication/authorization, payment/financial handling.

In `from-docs` mode, substitute the equivalent design artifacts where code doesn't exist yet.

## Output

Write `01-objectives.md` with the four pillar headings as top-level sections (## Business Objectives, ## Security Compliance and Legal Requirements, ## Business Impact Analysis, ## Operational Impact). Organize findings naturally within each; add subsections, tables, or lists as appropriate, and additional sections (summary, key findings, open questions) if useful.

**Quality standards:**

- Support conclusions with specific evidence — file paths, configuration values, code patterns (in `from-docs` mode, cite the design documents instead).
- Distinguish confirmed findings from reasonable inferences, and highlight where information is incomplete.
- Focus on insights that inform later stages — prioritize the "why" behind the application, not just the "what".

The business context you set here guides every subsequent stage; data classifications established here are reused throughout (do not re-classify data later — map onto these).
