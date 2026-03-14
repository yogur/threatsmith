"""PASTA Stage 3 — Application Decomposition prompt template."""

from threatsmith.prompts.contexts import DecompositionContext

STAGE_PROMPT = """\
You are a threat modeling analyst performing PASTA (Process for Attack Simulation \
and Threat Analysis) Stage 3 — Application Decomposition. Your task is to decompose \
the application into its security-relevant structural elements: use cases, actors, \
entry points, assets, data flows, and trust boundaries. This decomposition bridges \
the business context (Stage 1) and technical inventory (Stage 2) with the threat \
analysis that follows in Stage 4.

Your analysis produces the structural foundation that downstream agents need to \
identify threats, vulnerabilities, and attack paths. Every component you document \
here becomes a potential target in Stage 4's STRIDE analysis. Every data flow you \
diagram becomes a path that Stage 6 will model attacks against. Completeness and \
accuracy are critical — what you miss here will be invisible to all subsequent stages.

Your task is to analyze the codebase in the current working directory and produce \
a comprehensive application decomposition covering the five pillars below.

{prior_stages_section}

## ANALYSIS PILLARS

Your analysis must address each of the following five pillars. These correspond to \
required top-level sections in your output.

### 1. Use Case Identification

Identify and document the application's use cases with a focus on security relevance:

- **Core use cases:** What are the primary functions the application provides? Derive \
these from the business objectives identified in Stage 1 and the technical components \
mapped in Stage 2.
- **Security-critical use cases:** Which use cases involve authentication, \
authorization, data access, privilege escalation, payment processing, secret \
management, or other security-sensitive operations?
- **Administrative use cases:** What management, configuration, deployment, and \
maintenance operations does the application support?
- **Abuse cases:** For each significant use case, identify how it could be misused \
by a malicious actor. What happens if inputs are manipulated, steps are skipped, or \
the use case is invoked in an unintended context? Abuse cases directly feed Stage 4's \
threat identification.
- **Use case to component mapping:** Which code modules, services, and infrastructure \
components participate in each use case? Reference specific file paths and code \
patterns.

### 2. Actors, Roles, and Trust Levels

Identify all entities that interact with the system and classify their trust levels:

- **Human actors:** End users, administrators, operators, developers, support staff, \
and any other human roles that interact with the application.
- **External system actors:** Third-party services, partner APIs, identity providers, \
payment processors, analytics services, CDNs, and any external system that sends \
data to or receives data from the application.
- **Internal system actors:** Background workers, scheduled tasks, message queue \
consumers and producers, internal microservices, cron jobs, and automated processes \
that operate within the application boundary.
- **Role hierarchy and privilege levels:** Document the privilege model — what roles \
exist, what permissions each role grants, and how privilege escalation works (or \
should be prevented). Include both explicit roles defined in code and implicit roles \
(e.g., "anyone with SSH access to the server").

**Trust level classification:** Assign each actor a trust level:
- **Untrusted / Public:** No authentication required. Internet-facing. Input must be \
treated as hostile.
- **Semi-trusted / Authenticated:** Identity verified but limited authorization. \
Standard user access.
- **Trusted / Internal:** Internal services, background processes, or staff with \
elevated but scoped access.
- **Privileged / Administrative:** Full or near-full system access. Actions can \
modify security controls, access all data, or alter system behavior.

**Actor-to-entry-point mapping:** For each actor, document which entry points they \
can access and through what authentication and authorization mechanisms.

### 3. Entry Points and Attack Surface

Catalog every way external entities can interact with the application:

- **API endpoints:** REST routes, GraphQL operations, gRPC services, SOAP endpoints. \
For each, document the HTTP method, path, authentication requirement, and data \
accepted.
- **Web interface endpoints:** Pages, forms, file upload handlers, WebSocket \
connections, Server-Sent Events.
- **CLI commands and arguments:** Command-line interfaces, management commands, \
administrative scripts.
- **Background and event-driven entry points:** Message queue consumers, event \
handlers, webhook receivers, pub/sub subscribers, scheduled tasks, cron jobs.
- **Administrative and management interfaces:** Admin panels, health check endpoints, \
metrics endpoints, debug endpoints, database management interfaces.
- **Implicit entry points:** File system watchers, configuration file reloads, \
environment variable changes, deployment triggers, hot-reload mechanisms.
- **Network-level entry points:** Exposed ports, protocols, and services beyond \
the application layer (database ports, cache ports, management ports).

For each entry point, document:
- Protocol and transport mechanism
- Authentication and authorization requirements
- Trust level of expected callers
- Data accepted (input types, formats, size limits)
- Data returned (output types, sensitivity classification)

### 4. Assets and Data Inventory

Identify all valuable resources and document the data landscape:

**Assets:**
- **Data stores:** Databases, file systems, object storage, caches, session stores, \
search indices — what data each holds, access controls, and backup/recovery mechanisms.
- **Services:** Application services, third-party integrations, infrastructure \
services — their availability requirements and failure impact.
- **Configuration and secrets:** API keys, tokens, certificates, encryption keys, \
connection strings, environment variables — how they are stored, accessed, and rotated.
- **Infrastructure:** Compute resources, network resources, DNS, load balancers, \
CDNs — what is critical for availability and integrity.

**Data inventory:**
- Catalog all data types the application handles, using the data classification \
levels established in Stage 1 (public, internal, confidential, restricted).
- For each data type, document: where it originates (sources), where it is stored \
(at rest), where it is sent (sinks), and who can access it.
- Distinguish data at rest from data in motion — the same data type may have \
different security properties depending on its state.
- Document data ownership: which component or service is the authoritative source \
for each data type?
- Identify data aggregation risks: individually innocuous data that becomes \
sensitive when combined.

### 5. Data Flow Diagrams and Trust Boundaries

Create Mermaid diagrams that visualize data movement through the system with \
explicit trust boundaries. These diagrams are critical deliverables — they will be \
referenced by every subsequent stage.

**Required diagrams (minimum two):**

**Diagram 1 — Architecture Overview with Trust Boundaries:**
A high-level diagram showing all major components, external entities, data stores, \
and the trust boundaries between security zones. Use subgraph blocks to represent \
trust zones (e.g., "Public Internet", "DMZ", "Application Tier", "Data Tier", \
"External Services"). Show the primary data flows between zones.

**Diagram 2 — Sensitive Data Flow:**
A detailed diagram tracing the flow of the most sensitive data types (as classified \
in Stage 1) from ingestion to storage and retrieval. Show each processing step, \
transformation, and trust boundary crossing. Label flows with data classification \
levels.

**Additional diagrams** as warranted by complexity — for example, authentication \
flow, payment processing flow, or inter-service communication patterns.

**Diagram guidelines:**
- Use Mermaid flowchart syntax with subgraph blocks for trust boundaries
- Label all data flows with what data moves and its classification level
- Show direction of data flow with arrows
- Include external entities, processes, data stores as distinct node shapes
- Document trust boundary crossings explicitly — these are the highest-risk \
points in the architecture
- Avoid parentheses inside node labels — use hyphens or commas instead \
(e.g., `Auth[Auth Module - JWT, OIDC]` not `Auth[Auth Module (JWT, OIDC)]`)

**Trust boundary documentation:**
Beyond the diagrams, provide a written inventory of all trust boundaries:
- Boundary name and description
- What crosses the boundary (data types, commands, events)
- Direction of crossing (inbound, outbound, bidirectional)
- Security controls at the boundary (authentication, encryption, validation, \
rate limiting)
- Whether the boundary is existing or proposed

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Entry Point and Routing Discovery (start here):**
Map all ways into the application:
- Route definitions, URL patterns, and API endpoint registrations
- OpenAPI/Swagger specifications and API documentation
- CLI argument parsers and command registrations
- Event handler registrations, webhook endpoints, and message queue bindings
- Middleware chains and request pipelines — what processing occurs before \
reaching application logic
- Socket listeners and network service bindings

**Phase 2 — Actor and Asset Tracing:**
Identify who interacts with the system and what they interact with:
- Authentication middleware, login flows, and identity verification
- Authorization checks, role definitions, permission models, and access control \
lists
- User model definitions and role enumerations
- Data model definitions, database schemas, and migration files
- Service interface definitions and inter-service contracts
- Configuration and secrets management patterns
- Session management and state persistence

**Phase 3 — Data Flow and Trust Boundary Mapping:**
Trace data from entry to storage and back, identifying every boundary crossing:
- Follow request processing from entry point through middleware, business logic, \
data access, and response generation
- Identify where data is validated, sanitized, transformed, encrypted, or \
logged at each stage
- Map trust boundary crossings: where does data move between security zones?
- Identify data that leaves the system boundary (outbound API calls, webhooks, \
email, logging to external services)
- Trace sensitive data paths end-to-end — from user input to persistent storage \
and back to display
- Build your Mermaid DFDs as you trace these flows

## OUTPUT REQUIREMENTS

Write your analysis to `{output_dir}03-application-decomposition.md`. Create the \
`{output_dir}` directory if it does not already exist.

Structure your output with the five pillar headings as top-level sections \
(## Use Case Identification, ## Actors Roles and Trust Levels, \
## Entry Points and Attack Surface, ## Assets and Data Inventory, \
## Data Flow Diagrams and Trust Boundaries). Within each section, organize your \
findings naturally based on what you discover — add subsections, tables, or lists \
as appropriate. You may include additional sections if your investigation reveals \
important context.

**Diagram requirements:**
- Include at minimum two Mermaid diagrams (architecture overview with trust \
boundaries and sensitive data flow)
- Embed diagrams directly in the markdown using fenced code blocks with the \
`mermaid` language tag
- Each diagram must include a descriptive title and explanatory text

**Quality standards:**
- Provide specific evidence from the codebase to support conclusions (reference \
file paths, configuration values, code patterns)
- Every entry point must have its trust level and authentication requirement \
documented
- Every data type must be mapped to its Stage 1 classification level
- Trust boundaries must be documented both visually (in diagrams) and textually \
(in written inventory)
- Clearly distinguish between confirmed findings and reasonable inferences
- Highlight areas where you have incomplete information or where additional \
investigation would be valuable
- Abuse cases must be tied to specific use cases — generic threats belong in \
Stage 4, not here

Your decomposition defines the structural map that all subsequent stages navigate. \
Stage 4 will apply STRIDE to every component and data flow you identify. Stage 5 \
will search for vulnerabilities in every entry point you catalog. Stage 6 will \
model attacks along every path you trace. What you miss here, they miss entirely.
"""


def build_prompt(context: DecompositionContext, output_dir: str = "threatmodel") -> str:
    """Build the complete Stage 3 prompt with optional Stages 1-2 output injection.

    Args:
        context: DecompositionContext with optional stage_01_output and
                 stage_02_output markdown from prior stages.
        output_dir: Output directory for deliverables (defaults to "threatmodel").
                   Accepts with or without trailing slash.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.stage_01_output or None
    stage_02_output = context.stage_02_output or None
    normalized_dir = output_dir.rstrip("/") + "/"

    if stage_01_output or stage_02_output:
        parts = [
            "## PRIOR STAGE FINDINGS\n",
            "The following outputs from prior stages provide the business context, "
            "data classifications, and technical scope that must inform your "
            "application decomposition. Use the Stage 1 data sensitivity "
            "classifications when documenting data types. Use the Stage 2 technical "
            "scope to understand the components, dependencies, and boundaries you "
            "are decomposing.\n",
            "<prior_stages>",
        ]

        if stage_01_output:
            parts.append("<stage_01_objectives>")
            parts.append(stage_01_output)
            parts.append("</stage_01_objectives>")

        if stage_02_output:
            parts.append("<stage_02_technical_scope>")
            parts.append(stage_02_output)
            parts.append("</stage_02_technical_scope>")

        parts.append("</prior_stages>")
        prior_stages_section = "\n".join(parts)
    else:
        prior_stages_section = ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    return prompt.replace("{output_dir}", normalized_dir)
