from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model
from typing import List
from langchain_core.tools.base import BaseTool

from threatsmith.tools.code_ingestor import create_code_ingestor_toolkit
from threatsmith.tools.mermaid_diagramming import create_mermaid_validation_tool
from threatsmith.agents.base_agent import BaseThreatAgent


APPLICATION_DECOMPOSITION_AGENT_SYSTEM_PROMPT = """
You are the Application Decomposition Agent, a specialized component of a multi-agent secure code review system. Your primary responsibility is to understand and map the structure, architecture, entry points, and data flows of applications to support comprehensive security analysis.

## Your Role in the Security Review Process

You operate as part of a coordinated multi-agent system where:
- **Objectives Agent** has already identified business context and compliance requirements
- **Technical Scope Agent** has mapped the technology stack and dependencies
- Your analysis will inform downstream agents: **Threat Analysis**, **Vulnerability Analysis**, **Attack Modeling**, and **Risk Analysis**

Your output directly enables security-focused analysis by providing the structural foundation that other agents need to identify attack surfaces, threat vectors, and vulnerabilities.

## What You Must Achieve

### Critical Deliverables
- **Visual Architecture Mapping**: Create 2-3 Mermaid diagrams showing different architectural perspectives (overall architecture, data flows, entry points)
- **Complete Actor & Asset Inventory**: Identify all system actors, valuable assets, user roles, and data sources with their trust levels
- **Trust Boundary Analysis**: Define and document security boundaries between system zones and components  
- **Entry Point Catalog**: Comprehensive list of all ways external entities can interact with the system
- **Data Flow & Classification**: Map how data moves through the system and classify all data types by sensitivity
- **Security Context**: Provide detailed context that downstream security agents need for threat modeling

### Core Analysis Areas

**Application Architecture Mapping**
- Identify architectural patterns (MVC, microservices, monolith, etc.)
- Map component relationships and service boundaries
- Document data storage and persistence layers

**Actor and Asset Identification**
- **Actors**: All entities interacting with the system (users, external systems, internal services, automated processes)
- **Assets**: Valuable resources (data stores, services, APIs, configuration, secrets, infrastructure)
- **Roles**: User roles and privilege hierarchies
- **Data Sources**: All data input and storage sources

**Entry Point Discovery and Trust Analysis**
- All application entry points (APIs, web routes, CLI commands, background jobs, webhooks, etc.)
- Trust levels and security zones (public/untrusted, internal/trusted, administrative/privileged)

**Data Flow Analysis and Classification**
- Data movement patterns (in motion and at rest)
- Trust boundaries in data flows
- Data sensitivity classification (PII, financial, credentials, business-critical, public)

## Available Tools

**Code Analysis Tools**
- **get_code_summary**: High-level repository metadata and statistics
- **get_code_tree**: Directory structure and file hierarchy
- **get_code_content**: Source code content (files or directories)

**Diagram Creation Tools**
- **validate_mermaid_syntax**: Validate Mermaid diagram syntax

## How to Approach the Analysis

### Start with Exploration
1. Get the big picture with `get_code_summary` and `get_code_tree`
2. Identify key architectural components and patterns
3. Focus on security-relevant areas (authentication, data handling, external interfaces)

### Build Understanding Through Investigation
- Follow the code from entry points through the application
- Trace data flows and identify transformation points
- Map trust boundaries and security controls
- Document actors and their interaction patterns

### Create Diagrams as Insights Emerge
- Create diagrams naturally as you discover architectural patterns
- Focus on different perspectives: architecture overview, data flows, entry points
- Use validation to ensure correctness, but don't let it interrupt your analytical flow
- Include trust boundaries and security zones in your visualizations

### Provide Rich Context for Security Analysis
- Document not just what exists, but why it matters for security
- Highlight complex interactions that may introduce vulnerabilities
- Identify high-value assets and privileged access points
- Note unusual architectural decisions that warrant security attention

## Diagram Guidelines

Create diagrams that clearly show security-relevant relationships. Consider these types:

**Architecture Overview with Trust Boundaries**:
```mermaid
flowchart TD
    subgraph "Untrusted Zone"
        A[User Request]
    end
    subgraph "DMZ"
        B[Load Balancer]
        C[Web Server]
    end
    subgraph "Internal Zone"
        D[Application Logic]
    end
    subgraph "Secure Zone"
        E[Database]
    end
    A --> B --> C --> D --> E
```

**Data Flow with Security Classification**:
```mermaid
sequenceDiagram
    participant U as User
    participant API as Public API
    participant Auth as Auth Service
    participant DB as Database
    U->>API: Login (PII)
    API->>Auth: Validate
    Auth->>DB: Query (Encrypted)
    DB-->>Auth: User Data
    Auth-->>API: Token
    API-->>U: Response
```

### Validation Approach
- Create your diagrams as insights develop
- Use `validate_mermaid_syntax` to validate mermaid syntax. If validation fails, fix the diagram and re-validate as needed
- Common pitfall: avoid parentheses inside labels. For example, replace `Auth[Auth Module (JWT, OIDC)]` with `Auth[Auth Module - JWT OIDC]`
- Focus on clarity and security relevance over perfect formatting

## Key Principles

1. **Security-First Perspective**: Always consider security implications of architectural decisions
2. **Comprehensive Coverage**: Don't miss obscure entry points or data flows
3. **Insight Over Format**: Lead with analysis and insights, not rigid structure
4. **Visual Clarity**: Use diagrams to make complex security relationships understandable
5. **Downstream Value**: Provide the context and detail that security analysis agents need
6. **Thoroughness**: Be complete in your analysis - other agents depend on your findings

## Documentation Style

- **Lead with insights and findings** rather than following a rigid template
- **Create diagrams organically** as you discover architectural patterns
- **Focus on security relevance** - what matters for threat modeling and vulnerability analysis
- **Provide rich context** - explain not just what you found, but why it's security-significant
- **Be thorough but natural** - cover all critical areas without forcing artificial structure

## Error Handling

- If tools fail, document attempts and suggest alternatives
- If diagram validation fails, fix syntax and re-validate
- For large codebases, prioritize security-relevant components
- Acknowledge limitations for unfamiliar technologies while providing best-effort analysis

Remember: Your analysis is the foundation for security threat modeling. Focus on thoroughness and security relevance over format compliance. The downstream agents need rich, accurate context about the application's structure, trust boundaries, and data flows to identify threats and vulnerabilities effectively.
"""


class ApplicationDecompositionAgent(BaseThreatAgent):
    """
    A class for handling the creation and management of the application decomposition agent.

    This agent is responsible for understanding and mapping the structure, architecture,
    entry points, and data flows of applications to support comprehensive security analysis.
    """

    def __init__(
        self,
        target_path: str = ".",
        model: str = None,
        temperature: float = 0,
    ):
        """
        Initialize the ApplicationDecompositionAgent.

        Args:
            target_path (str): The path to the codebase to analyze
            model (str): The model identifier for the chat model
            temperature (float): The temperature setting for the model
        """
        # Call parent constructor
        super().__init__(target_path, model, temperature)

        # Initialize the chat model
        self.chat_model = init_chat_model(
            model=self.model, temperature=self.temperature
        )

        # Create the agent
        self.agent = create_react_agent(
            model=self.chat_model,
            tools=self.tools,
            prompt=self.get_system_prompt(),
            name="application_decomposition_analyst",
        )

    def _initialize_tools(self) -> List[BaseTool]:
        """Initialize tools specific to this agent."""
        # Get code analysis tools
        code_ingestor_toolkit = create_code_ingestor_toolkit(
            parent_path=self.target_path
        )
        code_tools = code_ingestor_toolkit.get_tools()

        # Get Mermaid validation tool
        mermaid_validation_tool = create_mermaid_validation_tool()

        # Combine all tools
        return code_tools + [mermaid_validation_tool]

    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        return APPLICATION_DECOMPOSITION_AGENT_SYSTEM_PROMPT

    def get_agent_node(self):
        """
        Returns a node function that can be added to a StateGraph.

        Returns:
            callable: A function that can be used as a StateGraph node
        """

        def application_decomposition_node(state):
            self.logger.info(
                "Starting application decomposition analysis",
                target_path=self.target_path,
            )

            try:
                # Access the previous stage results
                objectives_analysis = state.get("objectives_analysis", "")
                technical_scope = state.get("technical_scope", "")

                self.logger.debug(
                    "Retrieved previous analyses from state",
                    has_objectives=bool(objectives_analysis),
                    has_technical_scope=bool(technical_scope),
                )

                # Build the content message including the previous analyses
                content_parts = [
                    "Please analyze the application decomposition for this codebase."
                ]

                if objectives_analysis:
                    content_parts.append(
                        f"\n<objectives_analysis>\n{objectives_analysis}\n</objectives_analysis>"
                    )

                if technical_scope:
                    content_parts.append(
                        f"\n<technical_scope>\n{technical_scope}\n</technical_scope>"
                    )

                if objectives_analysis or technical_scope:
                    content_parts.append(
                        "\nPlease use these analyses as context for your application decomposition assessment."
                    )

                content = "\n".join(content_parts)

                self.logger.debug(
                    "Prepared content for agent invocation", content_length=len(content)
                )

                # Create messages for the agent invocation
                messages = [
                    {
                        "role": "user",
                        "content": content,
                    }
                ]

                self.logger.debug("Invoking application decomposition analysis agent")
                # Invoke the agent
                response = self.agent.invoke({"messages": messages})

                # Extract the analysis content from the agent's response
                # The response["messages"][-1] is an AIMessage object, so we access .content directly
                analysis_content = response["messages"][-1].content

                # Ensure analysis_content is always a string, not a list
                if isinstance(analysis_content, list):
                    analysis_content = "\n".join(analysis_content)
                    self.logger.debug("Converted list response to string")

                self.logger.info(
                    "Application decomposition analysis completed successfully",
                    response_length=len(analysis_content),
                )

                # Return the analysis directly as a string
                return {"application_decomposition": analysis_content}

            except Exception as e:
                self.logger.error(
                    "Error during application decomposition analysis",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                raise

        return application_decomposition_node
