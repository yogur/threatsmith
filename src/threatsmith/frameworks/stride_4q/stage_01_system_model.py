"""4QF+STRIDE Stage 1 — System Model prompt template."""

from threatsmith.frameworks.types import StageContext

STAGE_PROMPT = """\
You are a threat modeling analyst performing 4QF+STRIDE Stage 1 — System Model. \
This stage answers the first question of the Four Question Framework: \
"What are we working on?" Your analysis establishes the comprehensive application \
model that forms the foundation for systematic threat identification in Stage 2.

Your task is to analyze the codebase in the current working directory and produce \
a detailed system model covering all aspects of the application's architecture, \
data flows, and attack surface.

## ANALYSIS AREAS

### 1. Application Purpose and Scope

Establish a clear understanding of what the application does:

- What business problem does this application solve?
- Who are the intended users, customers, and stakeholders?
- What are the key business functions and workflows?
- What is the business domain and industry context?
- What are the critical operations that depend on this application?

### 2. Technology Stack

Inventory the technologies, frameworks, and platforms in use:

- Programming languages and framework versions
- Web frameworks, application servers, and middleware
- Databases, caches, and message queues
- Third-party libraries and their roles
- Build tools, package managers, and CI/CD tooling
- Cloud services, infrastructure-as-code, and deployment targets

### 3. Data Flows

Map how data moves through the system:

- Data ingestion points (user input, API calls, file uploads, webhooks)
- Data processing pipelines and transformations
- Data storage locations and persistence mechanisms
- Data output channels (API responses, UI rendering, exports, notifications)
- Data shared with or received from external systems
- Sensitive data types handled (PII, credentials, financial data, health data)

### 4. Actors and Assets

Identify who interacts with the system and what needs protection:

- User roles and their capabilities (anonymous, authenticated, admin, service)
- External systems and services that interact with the application
- Data assets requiring protection (classified by sensitivity)
- Infrastructure assets (servers, containers, secrets stores)
- Intellectual property and business logic assets

### 5. Trust Boundaries

Identify boundaries where trust levels change:

- Network boundaries (public internet, DMZ, internal network, VPN)
- Authentication boundaries (unauthenticated vs. authenticated zones)
- Authorization boundaries (role-based access transitions)
- Process boundaries (client vs. server, frontend vs. backend, microservice borders)
- Third-party boundaries (where data leaves organizational control)
- Data classification boundaries (where data sensitivity levels change)

### 6. Entry Points

Catalog all ways external entities can interact with the system:

- HTTP/HTTPS endpoints (REST APIs, GraphQL, web pages, webhooks)
- WebSocket connections and real-time channels
- CLI interfaces and management consoles
- Message queue consumers and event handlers
- File system interfaces (uploads, config files, log directories)
- Database connections and administrative interfaces
- Service mesh and inter-service communication channels

### 7. External Dependencies

Map the external systems and services the application relies on:

- Third-party APIs and SaaS integrations
- Authentication providers (OAuth, SAML, SSO)
- Cloud platform services (storage, compute, networking, secrets)
- CDN and edge services
- Monitoring, logging, and alerting services
- Payment processors and financial service integrations

### 8. Deployment Context

Describe how the application is deployed and operated:

- Deployment architecture (monolith, microservices, serverless, hybrid)
- Container orchestration and runtime environment
- Environment tiers (development, staging, production)
- Network topology and segmentation
- Secrets management and configuration approach
- Scaling and high-availability characteristics

{user_objectives_section}

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Documentation and Configuration:**
- README files, docs directories, API specifications
- Package manifests and dependency files
- Deployment configs (Dockerfiles, Kubernetes manifests, terraform, CI/CD)
- Environment variable definitions and configuration schemas

**Phase 2 — Architecture and Data Layer:**
- Application entry points, routing, and middleware
- Database schemas, migrations, and data models
- Data access patterns and query builders
- Authentication and authorization mechanisms

**Phase 3 — Integration and Business Logic:**
- Service-to-service communication
- External API integrations and third-party clients
- Core business logic and workflow implementations
- Event handling and asynchronous processing

## DATA FLOW DIAGRAMS

You MUST produce at least one Mermaid data flow diagram (DFD) showing:
- Major components and their interactions
- Data flows with labels indicating what data is transmitted
- Trust boundaries as subgraphs
- External entities and data stores

Use Mermaid `flowchart` or `graph` syntax. Example structure:
```mermaid
flowchart LR
    subgraph "Trust Boundary: Public"
        User[User Browser]
    end
    subgraph "Trust Boundary: Application"
        API[API Server]
        Auth[Auth Service]
    end
    subgraph "Trust Boundary: Data"
        DB[(Database)]
    end
    User -->|"HTTPS requests"| API
    API -->|"Verify tokens"| Auth
    API -->|"Read/Write"| DB
```

Include additional diagrams if the architecture warrants it (e.g., separate \
diagrams for deployment architecture, data flow per major feature, or \
authentication flow).

## OUTPUT REQUIREMENTS

Write your analysis to `{output_dir}01-system-model.md`. Create the \
`{output_dir}` directory if it does not already exist.

Structure your output with clear top-level sections covering each analysis area. \
Include the Mermaid DFD(s) in the appropriate section. Add subsections, tables, \
or lists as the architecture warrants.

**Quality standards:**
- Provide specific evidence from the codebase (file paths, configuration values, \
code patterns) to support your findings
- Clearly distinguish between confirmed findings and reasonable inferences
- Highlight areas where information is incomplete or further investigation is needed
- Focus on architectural understanding that will directly inform threat \
identification in Stage 2
- Be thorough but prioritize breadth of coverage over implementation details — \
the goal is a complete map of the system, not a code review

Your system model establishes the scope and structure for the entire threat \
modeling engagement. Every component, data flow, and trust boundary you identify \
here will be systematically analyzed for threats in Stage 2.
"""


def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
    """Build the complete Stage 1 prompt with optional user-supplied objectives.

    Args:
        context: StageContext with optional user_objectives dict containing
                 "business_objectives" and "security_objectives" strings.
        output_dir: Output directory for deliverables (defaults to "threatmodel").
                   Accepts with or without trailing slash.

    Returns:
        The fully assembled prompt string.
    """
    objectives = context.user_objectives or {}
    business_objectives = objectives.get("business_objectives") or None
    security_objectives = objectives.get("security_objectives") or None
    normalized_dir = output_dir.rstrip("/") + "/"

    if business_objectives or security_objectives:
        parts = ["## USER-SUPPLIED OBJECTIVES", ""]
        parts.append(
            "The user has provided the following objectives as reference points. "
            "Use these to guide and validate your analysis, but still conduct "
            "your own independent investigation. Note any discrepancies between "
            "the provided objectives and what you discover in the codebase."
        )
        parts.append("")

        if business_objectives:
            parts.append(f"**Business Objectives:**\n{business_objectives}")
            parts.append("")

        if security_objectives:
            parts.append(f"**Security Objectives:**\n{security_objectives}")
            parts.append("")

        user_objectives_section = "\n".join(parts)
    else:
        user_objectives_section = ""

    prompt = STAGE_PROMPT.replace("{user_objectives_section}", user_objectives_section)
    return prompt.replace("{output_dir}", normalized_dir)
