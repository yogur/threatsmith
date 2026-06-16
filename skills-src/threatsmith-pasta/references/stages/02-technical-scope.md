# Stage 2 — Define Technical Scope

This stage establishes the technical boundaries of the threat model: the attack-surface boundary — what is in scope, what touches sensitive data, and what the blast radius would be if any component were compromised or modified. **This is not a technology inventory.** You map the technical environment onto the data classifications and business context from Stage 1.

**Deliverable:** write your analysis to `02-technical-scope.md` in the output directory (default `threatmodel/`).

## Read the prior stage

Read `01-objectives.md` from the output directory. Use its data-sensitivity classifications and business-impact analysis to assess the security impact of each technical component you identify.

## Mode framing

- **from-code** — Map the actual stack, dependencies, and infrastructure declared in the repository. Manifests, container/CI/IaC files, and config are the primary source of truth; docs corroborate.
- **from-docs** — Map the *intended* technical environment from the design: the stack the design specifies, the integrations and infrastructure it commits to, and the trust boundaries it implies. Flag where technical choices are still undecided.
- **pair** — Draft the scope from available material and ask the human about the stack, dependencies, deployment model, and external integrations you can't see.

## Analysis pillars

Address each of these six pillars (they become the top-level sections of your output):

1. **Project boundary definition** — what is in scope (the project, its direct dependencies, infrastructure it provisions); what is adjacent but out of scope (shared infrastructure, upstream services, platform capabilities it consumes but doesn't control); trust boundaries between this project and external systems (what crosses, in which direction, at what trust level); interactions with shared subsystems and the access levels held; and implicit boundaries from deployment model, network segmentation, or ownership.
2. **Technology stack mapping** — languages, frameworks, middleware, runtimes, build systems and package managers, datastores/brokers/caches/search, auth technologies and protocols (OAuth, SAML, JWT, LDAP), API and communication protocols (REST, gRPC, GraphQL, WebSocket, AMQP), cryptographic libraries and key management, and observability tooling. Note versions where determinable. Focus on manifests that declare dependencies directly (package.json, requirements.txt, pyproject.toml, pom.xml, Cargo.toml, go.mod, Gemfile, .csproj); avoid lock files (too large, resolved trees rather than direct declarations).
3. **Dependency and supply-chain analysis** — inventory direct dependencies (production vs. development), dependency coupling and purpose, registry sources and integrity mechanisms (lock files, checksums, signatures, pinned vs. ranged versions), build-time vs. runtime dependencies and their distinct risk profiles, and internal/organizational dependencies. **Level-of-impact assessment** for each significant dependency: what data classification it touches (reference Stage 1), the blast radius if compromised (malicious update or vuln disclosure), the ripple effect on other consumers of a shared subsystem, and maintenance/community health.
4. **Data classification and flow boundaries** — map components to the Stage 1 data classifications (do **not** re-classify; map onto them): which components handle which levels; where data crosses trust boundaries (what data, from/to which component, through what mechanism, with what protections); encryption at rest and in transit per level; residency/sovereignty implications visible in config; and **cross-cutting impact** — when a component touching high-classification data is modified, what else is affected. Consider an impact matrix of components vs. classification levels with the nature of access (read/write/process/store/transmit).
5. **Infrastructure and deployment** — containerization (Dockerfiles, base images, registries, image scanning), orchestration (Kubernetes, Helm, Compose, service mesh), cloud configs (IAM, networking, storage, managed services), CI/CD pipelines (build/test/deploy gates, secrets injection, artifact signing, environment promotion), IaC (Terraform, CloudFormation, Pulumi, Ansible), environment separation (dev/staging/prod differences), and secrets management (storage, injection, rotation).
6. **Integration points and external attack surface** — exposed network interfaces (ports, protocols, endpoints and their auth), public API surface (documented and undocumented endpoints, versioning, rate limiting), third-party integrations (payment, identity, analytics, CDN, email), webhooks/callbacks (inbound and outbound), inter-service communication patterns, file upload/download interfaces and restrictions, and administrative/management interfaces (admin panels, health checks, debug and metrics endpoints).

## Investigation approach

- **Manifest and configuration analysis** — dependency declarations, container definitions, CI/CD configs, IaC files, environment/config files, deployment manifests.
- **Dependency and architecture tracing** — import/module graphs, service definitions and inter-service communication, DB connection and ORM/query setup, API routes/middleware/pipelines, auth middleware and guards, queue consumers/producers.
- **Boundary and impact assessment** — correlate the above against Stage 1's classifications and business impact: for each significant component or dependency, what data it touches and its blast radius; document trust-boundary crossings and their data flows; flag components where a change could cascade; and flag mismatches between data sensitivity and the security posture of the component handling it.

In `from-docs` mode, substitute the equivalent design artifacts where code doesn't exist yet.

## Output

Write `02-technical-scope.md` with the six pillar headings as top-level sections (## Project Boundary Definition, ## Technology Stack Mapping, ## Dependency and Supply Chain Analysis, ## Data Classification and Flow Boundaries, ## Infrastructure and Deployment, ## Integration Points and External Attack Surface). Add subsections, tables, or lists as appropriate.

**Quality standards:**

- Support conclusions with specific evidence — file paths, configuration values, code patterns (or design documents in `from-docs` mode).
- For each significant dependency and component, document its level of impact — what data it touches, who else uses it, what happens if it is compromised.
- Distinguish confirmed findings from reasonable inferences, and highlight gaps or mismatches between technical posture and data-sensitivity requirements.
- Include an impact summary mapping components to data classification levels where possible.
- Prioritize security-relevant detail — components that touch sensitive data, cross trust boundaries, or have broad blast radius.

This stage defines the technical attack surface that all subsequent stages use. Every threat in Stage 4 and every vulnerability in Stage 5 must fall within the boundaries you establish here.
