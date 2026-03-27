"""PASTA Stage 2 — Define Technical Scope prompt template."""

from threatsmith.frameworks.types import StageContext

STAGE_PROMPT = """\
You are a threat modeling analyst performing PASTA (Process for Attack Simulation \
and Threat Analysis) Stage 2 — Define Technical Scope. Your task is to establish \
the technical boundaries of the threat model by mapping the project's technical \
environment, assessing the security-relevant impact of each component and \
dependency, and documenting how the technical landscape intersects with the data \
classifications and business context established in Stage 1.

This is NOT a technology inventory. You are defining the attack surface boundary — \
what is in scope, what touches sensitive data, and what the blast radius would be \
if any component were compromised or modified.

Your task is to analyze the codebase in the current working directory and produce \
a comprehensive technical scope analysis covering the six pillars below.

{prior_stages_section}

## ANALYSIS PILLARS

Your analysis must address each of the following six pillars. These correspond to \
required top-level sections in your output.

### 1. Project Boundary Definition

Establish clear boundaries for the threat model's technical scope:

- What is in scope for this analysis? Define the project itself, its direct \
dependencies, and infrastructure it configures or provisions.
- What is adjacent but out of scope? Identify shared infrastructure, upstream \
services, or platform capabilities the project consumes but does not control.
- Where are the trust boundaries between this project and external systems? \
Document each boundary explicitly — what crosses it, in which direction, and \
with what level of trust.
- How does this project interact with shared subsystems? What access levels \
(read, write, admin) does it have to those subsystems' data and APIs?
- What are the implicit boundaries created by deployment model, network \
segmentation, or organizational ownership?

### 2. Technology Stack Mapping

Catalog the technologies that compose the project's technical environment. For \
each significant technology, note the version if determinable:

- Programming languages (primary and secondary)
- Web frameworks, application frameworks, and middleware
- Runtime environments and platform requirements
- Build systems, package managers, and toolchains
- Database technologies, message brokers, caching layers, and search engines
- Authentication and authorization technologies and protocols (OAuth, SAML, \
JWT, LDAP, etc.)
- API technologies and communication protocols (REST, gRPC, GraphQL, \
WebSocket, AMQP, etc.)
- Cryptographic libraries and key management approaches
- Logging, monitoring, and observability tooling

Note: Focus on configuration files that declare dependencies directly \
(package.json, requirements.txt, pyproject.toml, pom.xml, Cargo.toml, go.mod, \
Gemfile, .csproj, etc.). Avoid lock files (yarn.lock, poetry.lock, etc.) as \
they are too large and contain resolved trees rather than direct declarations.

### 3. Dependency and Supply Chain Analysis

Analyze the project's dependency landscape with a focus on security impact:

- Inventory direct dependencies, distinguishing production from development \
dependencies.
- Identify dependency relationships and coupling — which components of this \
project depend on which libraries, and for what purpose.
- Assess package registry sources and integrity verification mechanisms \
(lock files, checksums, signatures, pinned versions vs ranges).
- Distinguish build-time dependencies from runtime dependencies and their \
distinct risk profiles.
- Identify internal or organizational dependencies (shared libraries, \
internal packages, mono-repo cross-references).

**Level of Impact Assessment:** For each significant dependency, document:
- What data classification levels does the dependent component touch? \
(Reference Stage 1's data sensitivity findings.)
- If this dependency were compromised (malicious update, vulnerability \
disclosure), what is the blast radius? Which subsystems, data stores, and \
users would be affected?
- Does upgrading or modifying this dependency affect other consumers of the \
same subsystem? For example, if a shared library is upgraded and that library \
has access to restricted data, document the ripple effect on all users of \
that library.
- What is the maintenance status and community health of critical dependencies?

### 4. Data Classification and Flow Boundaries

Map the technical components to the data classifications established in Stage 1. \
Do NOT re-classify data — use the classifications from Stage 1 and map the \
technical landscape onto them:

- Which components handle which data classification levels (public, internal, \
confidential, restricted)?
- Where does data cross trust boundaries? Document each crossing: what data, \
from which component, to which component, through what mechanism, and with \
what protections.
- What encryption is applied at rest and in transit for each classification \
level?
- What are the data residency and sovereignty implications visible in \
configuration or deployment setup?
- **Cross-cutting impact analysis:** When a component that touches \
high-classification data is modified (code change, dependency upgrade, \
configuration update), what other components or users could be affected? \
Document these ripple effects explicitly.

Consider creating an impact matrix or table showing components versus data \
classification levels they access, with the nature of access (read, write, \
process, store, transmit).

### 5. Infrastructure and Deployment

Document the infrastructure and deployment patterns that form the operational \
boundary of the project:

- Containerization: Dockerfiles, base images, container registries, image \
scanning configuration
- Orchestration: Kubernetes manifests, Helm charts, Docker Compose, service \
mesh configurations
- Cloud provider configurations: IAM policies, networking rules, storage \
buckets, managed services (look for AWS, GCP, Azure configuration files)
- CI/CD pipeline definitions: build steps, test stages, deployment gates, \
secrets injection, artifact signing, environment promotion
- Infrastructure-as-code: Terraform, CloudFormation, Pulumi, Ansible
- Environment separation: how dev, staging, and production environments \
differ in configuration, access controls, and data exposure
- Secrets management: how secrets are stored, injected, and rotated \
(environment variables, vault integration, sealed secrets)

### 6. Integration Points and External Attack Surface

Identify all points where the project interfaces with external systems or \
exposes functionality:

- Exposed network interfaces: ports, protocols, endpoints, and their \
authentication requirements
- Public API surface area: documented and undocumented endpoints, API \
versioning, rate limiting
- Third-party service integrations: payment processors, identity providers, \
analytics services, CDNs, email services
- Webhook and callback configurations: inbound and outbound
- Inter-service communication patterns: synchronous vs asynchronous, \
service discovery, load balancing
- File upload/download interfaces and their restrictions
- Administrative and management interfaces: admin panels, health checks, \
debug endpoints, metrics endpoints

## INVESTIGATION APPROACH

Conduct your analysis in three phases:

**Phase 1 — Manifest and Configuration Analysis (start here):**
Examine project manifests and configuration files to establish the technical \
foundation:
- Package manifests and dependency declarations (package.json, requirements.txt, \
pyproject.toml, pom.xml, Cargo.toml, go.mod, Gemfile, .csproj, etc.)
- Container definitions (Dockerfile, docker-compose.yml)
- CI/CD configurations (.github/workflows, .gitlab-ci.yml, Jenkinsfile, \
.circleci, etc.)
- Infrastructure-as-code files (terraform, cloudformation, pulumi)
- Environment and configuration files (.env.example, config/, settings files)
- Deployment manifests (Kubernetes YAML, Helm charts)

**Phase 2 — Dependency and Architecture Tracing:**
Trace the dependency graph and architectural patterns:
- Import and module dependency graphs
- Service definitions and inter-service communication
- Database connection configurations and ORM/query layer setup
- API route definitions, middleware chains, and request pipelines
- Authentication and authorization middleware and guard implementations
- Message queue consumers and producers

**Phase 3 — Boundary and Impact Assessment:**
Correlate findings from Phases 1 and 2 against Stage 1's data sensitivity \
classifications and business impact analysis:
- For each significant component or dependency, assess what data classification \
levels it touches and what the impact radius would be if compromised
- Document trust boundary crossings with their data flows
- Identify components where a change (upgrade, patch, configuration change) \
could have cascading effects on other subsystems or users
- Flag any mismatches between the sensitivity of data accessed and the security \
posture of the component accessing it

## OUTPUT REQUIREMENTS

Write your analysis to `{output_dir}02-technical-scope.md`.

Structure your output with the six pillar headings as top-level sections \
(## Project Boundary Definition, ## Technology Stack Mapping, \
## Dependency and Supply Chain Analysis, ## Data Classification and Flow \
Boundaries, ## Infrastructure and Deployment, \
## Integration Points and External Attack Surface). Within each section, \
organize your findings naturally based on what you discover — add subsections, \
tables, or lists as appropriate. You may include additional sections if your \
investigation reveals important context.

**Quality standards:**
- Provide specific evidence from the codebase to support conclusions (reference \
file paths, configuration values, code patterns)
- For each significant dependency and component, document its level of impact — \
what data it touches, who else uses it, and what happens if it is compromised
- Clearly distinguish between confirmed findings and reasonable inferences
- Highlight gaps where you have incomplete information or where the project's \
technical posture does not match its data sensitivity requirements
- Include an impact summary showing components mapped to data classification \
levels where possible
- Focus on security-relevant technical details — prioritize components that \
touch sensitive data, cross trust boundaries, or have broad blast radius

Your analysis defines the technical attack surface that all subsequent stages \
will use. Every threat identified in Stage 4 and every vulnerability assessed \
in Stage 5 must fall within the boundaries you establish here.
"""


def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
    """Build the complete Stage 2 prompt with optional Stage 1 output injection.

    Args:
        context: StageContext with optional prior_outputs containing
                 "stage_01_output" markdown from Stage 1.
        output_dir: Output directory for deliverables (defaults to "threatmodel").
                   Accepts with or without trailing slash.

    Returns:
        The fully assembled prompt string.
    """
    stage_01_output = context.prior_outputs.get("stage_01_output") or None
    normalized_dir = output_dir.rstrip("/") + "/"

    if stage_01_output:
        prior_stages_section = (
            "## PRIOR STAGE FINDINGS\n\n"
            "The following output from Stage 1 (Define Objectives) provides the "
            "business context, data sensitivity classifications, and compliance "
            "requirements that must inform your technical scope analysis. Use these "
            "findings to assess the security impact of each technical component you "
            "identify — particularly the data classification levels and business "
            "impact analysis.\n\n"
            "<prior_stages>\n"
            "<stage_01_objectives>\n"
            f"{stage_01_output}\n"
            "</stage_01_objectives>\n"
            "</prior_stages>"
        )
    else:
        prior_stages_section = ""

    prompt = STAGE_PROMPT.replace("{prior_stages_section}", prior_stages_section)
    return prompt.replace("{output_dir}", normalized_dir)
