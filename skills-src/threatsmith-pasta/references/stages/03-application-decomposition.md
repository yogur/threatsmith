# Stage 3 — Application Decomposition

This stage decomposes the application into its security-relevant structural elements: use cases, actors, entry points, assets, data flows, and trust boundaries. It bridges the business context (Stage 1) and technical scope (Stage 2) into the structural map that the threat analysis navigates. Every component you document here becomes a potential target in Stage 4; every data flow you diagram becomes a path Stage 6 models attacks against. What you miss here is invisible to all later stages.

**Deliverable:** write your analysis to `03-application-decomposition.md` in the output directory (default `threatmodel/`).

## Read the prior stages

Read `01-objectives.md` and `02-technical-scope.md` from the output directory. Use Stage 1's data classifications when documenting data types, and Stage 2's technical scope to understand the components, dependencies, and boundaries you are decomposing.

## Mode framing

- **from-code** — Derive the decomposition from the actual routes, handlers, models, and middleware in the repository. Cite specific files and code patterns.
- **from-docs** — Decompose the *designed* system: the use cases, actors, entry points, and data flows the design describes. Frame entry points and trust boundaries as designed rather than observed, and note where the design leaves them unspecified.
- **pair** — Build the decomposition with the human, confirming actors, roles, entry points, and sensitive data flows as you go.

## Note the system's nature for downstream reference selection

As you catalog entry points and the technology landscape, explicitly record whether the system **exposes HTTP APIs**, **integrates an LLM/AI model**, or **has a mobile client**. These characteristics determine which OWASP reference checklists Stage 4 consults (API, LLM, Mobile), so calling them out here makes that selection accurate. If none apply beyond a standard web surface, say so.

## Analysis pillars

Address each of these five pillars (they become the top-level sections of your output):

1. **Use case identification** — core use cases (derived from Stage 1 objectives and Stage 2 components); security-critical use cases (authentication, authorization, data access, privilege escalation, payments, secret management); administrative use cases; **abuse cases** for each significant use case (how it could be misused — manipulated inputs, skipped steps, unintended context); and use-case-to-component mapping referencing specific files.
2. **Actors, roles, and trust levels** — human actors (users, admins, operators, developers, support); external system actors (third-party services, partner APIs, identity/payment providers, CDNs); internal system actors (workers, scheduled tasks, queue consumers/producers, internal services, cron); and the role hierarchy and privilege model (explicit and implicit roles). Assign each actor a **trust level**: Untrusted/Public (no auth, internet-facing, hostile input), Semi-trusted/Authenticated (identity verified, limited authorization), Trusted/Internal (internal services or staff with elevated scoped access), Privileged/Administrative (full or near-full access). Map each actor to the entry points they can reach and through what auth.
3. **Entry points and attack surface** — API endpoints (method, path, auth requirement, data accepted), web interface endpoints (pages, forms, uploads, WebSocket, SSE), CLI commands and admin scripts, background/event-driven entry points (queue consumers, event handlers, webhooks, pub/sub, scheduled tasks), administrative/management interfaces (admin panels, health/metrics/debug endpoints), implicit entry points (file watchers, config reloads, deployment triggers, hot reload), and network-level entry points (exposed ports/protocols/services). For each: protocol/transport, auth/authz requirements, expected caller trust level, data accepted (types, formats, size limits), and data returned (types, sensitivity).
4. **Assets and data inventory** — assets (data stores, services, configuration and secrets, infrastructure) with their access controls, availability requirements, and failure impact; and a data inventory using the Stage 1 classification levels: for each data type, where it originates, where it is stored, where it is sent, and who can access it; data at rest vs. in motion; data ownership; and data-aggregation risks (innocuous data that becomes sensitive when combined).
5. **Data flow diagrams and trust boundaries** — see below.

## Data flow diagrams

Create Mermaid diagrams visualizing data movement with explicit trust boundaries — these are critical deliverables referenced by every later stage. Produce **at least two**:

- **Diagram 1 — Architecture overview with trust boundaries:** all major components, external entities, and data stores, with trust zones as `subgraph` blocks (e.g. "Public Internet", "DMZ", "Application Tier", "Data Tier", "External Services") and the primary flows between zones.
- **Diagram 2 — Sensitive data flow:** trace the most sensitive data types (per Stage 1) from ingestion to storage and retrieval, showing each processing step, transformation, and trust-boundary crossing; label flows with classification levels.

Add more diagrams as complexity warrants (auth flow, payment flow, inter-service communication). Use `flowchart` syntax with `subgraph` trust zones, label flows with the data moved and its classification, and **avoid parentheses inside node labels** — use hyphens or commas (e.g. `Auth[Auth Module - JWT, OIDC]`, not `Auth[Auth Module (JWT, OIDC)]`).

Beyond the diagrams, provide a written **trust-boundary inventory**: boundary name and description, what crosses it (data, commands, events), direction (inbound/outbound/bidirectional), security controls at the boundary (auth, encryption, validation, rate limiting), and whether the boundary exists today or is proposed.

## Investigation approach

- **Entry-point and routing discovery** — route/URL/endpoint registrations, OpenAPI/Swagger specs, CLI parsers, event/webhook/queue bindings, middleware chains, socket listeners.
- **Actor and asset tracing** — auth middleware and login flows, authorization checks and role/permission models, user models and role enums, data models and schemas, service contracts, secrets management, session/state persistence.
- **Data-flow and trust-boundary mapping** — follow requests from entry through middleware, business logic, data access, and response; note where data is validated, sanitized, transformed, encrypted, or logged; map boundary crossings and data leaving the system; trace sensitive data end-to-end; build the Mermaid DFDs as you trace.

In `from-docs` mode, substitute the equivalent design artifacts where code doesn't exist yet.

## Output

Write `03-application-decomposition.md` with the five pillar headings as top-level sections (## Use Case Identification, ## Actors Roles and Trust Levels, ## Entry Points and Attack Surface, ## Assets and Data Inventory, ## Data Flow Diagrams and Trust Boundaries). Embed at least two Mermaid diagrams using fenced ` ```mermaid ` blocks, each with a descriptive title and explanatory text.

**Quality standards:**

- Support conclusions with specific evidence — file paths, configuration values, code patterns (or design documents in `from-docs` mode).
- Every entry point must have its trust level and auth requirement documented; every data type must map to its Stage 1 classification.
- Document trust boundaries both visually (diagrams) and textually (written inventory).
- Distinguish confirmed findings from reasonable inferences, and tie abuse cases to specific use cases (generic threats belong in Stage 4, not here).

Your decomposition is the structural map every later stage navigates. Stage 4 applies threat analysis to every component and data flow you identify; Stage 5 searches every entry point for vulnerabilities; Stage 6 models attacks along every path you trace.
