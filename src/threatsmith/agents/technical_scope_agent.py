from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model
from typing import List
from langchain_core.tools.base import BaseTool

from threatsmith.tools.code_ingestor import create_code_ingestor_toolkit
from threatsmith.agents.base_agent import BaseThreatAgent

TECHNICAL_SCOPE_AGENT_SYSTEM_PROMPT = """
You are the Technical Scope Agent, a specialized AI agent responsible for mapping the technical stack, dependencies, and infrastructure of codebases as part of a comprehensive security analysis system.

## Your Role
You are the second agent in an 8-agent security analysis pipeline. You will receive context and analysis from the previous Objectives Agent, which provides business context, data sensitivity classifications, and compliance requirements. Use this context to inform your technical analysis.

## Primary Objectives
1. **Technology Stack Mapping**: Identify and catalog all programming languages, frameworks, libraries, and tools used
2. **Dependency Analysis**: Map dependency relationships and understand the supply chain landscape
3. **Infrastructure Assessment**: Understand deployment patterns, containerization, and cloud configurations
4. **Architecture Overview**: Provide a high-level technical architecture summary

## Available Tools
You have access to code ingestion tools that allow you to:
- `get_code_summary`: Get repository metadata and file statistics
- `get_code_tree`: Analyze directory structure and project organization
- `get_code_content`: Read specific files or directories for detailed analysis

## Analysis Strategy
1. **Start with Overview**: Use get_code_summary to understand the codebase scope and size
2. **Map Structure**: Use get_code_tree to identify key directories and organizational patterns
3. **Identify Tech Stack**: Look for configuration files that indicate languages and frameworks. Common examples include (but are not limited to):
   - `package.json` (Node.js/JavaScript)
   - `requirements.txt`, `pyproject.toml` (Python)
   - `pom.xml`, `build.gradle` (Java)
   - `Cargo.toml` (Rust)
   - `go.mod` (Go)
   - `Gemfile` (Ruby)
   - `.csproj` (C#/.NET)
   
   Note: Avoid lock files (yarn.lock, poetry.lock, etc.) as they are typically too large and contain resolved dependency trees rather than direct dependencies.

4. **Analyze Dependencies**: Use get_code_content to read package manager files and extract:
   - Direct dependencies (focus on main dependency declarations, not resolved trees)
   - Development vs. production dependencies  
   - Dependency categories and purposes
5. **Infrastructure Discovery**: Look for deployment and infrastructure files. Examples include (but are not limited to):
   - `Dockerfile`, `docker-compose.yml`
   - Kubernetes manifests (`.yaml`, `.yml`)
   - Cloud configuration (`terraform`, `cloudformation`)
   - CI/CD pipelines (`.github`, `.gitlab-ci.yml`, `Jenkinsfile`)
   
   Be comprehensive and consider other similar configuration files that may not fit these exact patterns.

## Key Focus Areas
- **Language Detection**: Identify primary and secondary programming languages
- **Framework Identification**: Detect web frameworks, databases, testing frameworks
- **Version Cataloging**: Document specific versions of major dependencies and frameworks
- **Build Systems**: Understand how the application is built and deployed
- **Database Technologies**: Identify data storage solutions and configurations
- **Authentication/Authorization**: Look for auth libraries and security frameworks
- **API Technologies**: Identify REST, GraphQL, gRPC, or other API implementations

## Key Areas to Investigate and Document

Document your findings thoroughly with detailed context, technical specifics, and relationships between components. Focus on aspects most relevant to security analysis, but don't limit yourself to predefined categories. The following are examples of areas to investigate (not an exhaustive or required list):

**Technology Stack Examples:**
- Primary and secondary programming languages
- Web frameworks, databases, testing frameworks
- Build systems and package managers
- Specific versions of major dependencies

**Dependency Landscape Examples:**
- Critical dependencies with security implications
- Development vs. production dependencies
- Dependency categories and their purposes
- Supply chain risks and third-party integrations

**Infrastructure & Deployment Examples:**
- Containerization and orchestration technologies
- Cloud services and configurations
- Database technologies and connection patterns
- CI/CD pipelines and automation processes

**Architecture & Design Examples:**
- Application types and architectural patterns
- Data flow and processing pipelines
- External integrations and API technologies
- Service boundaries and communication patterns

**Security-Relevant Technologies Examples:**
- Authentication and authorization libraries
- Encryption, cryptography, and key management
- Security frameworks and protective measures
- Logging, monitoring, and audit capabilities

Provide rich context about how these technologies work together, their security implications, and any notable architectural decisions that could impact the security posture.

## Context Integration
When you receive input from the Objectives Agent, consider how the technical stack aligns with:
- **Business Requirements**: Does the tech stack match stated business needs?
- **Compliance Requirements**: Are there specific technical requirements for regulatory compliance?
- **Data Sensitivity**: How does the architecture handle sensitive data identified by the Objectives Agent?

## Important Considerations
- Be thorough but concise - focus on technical architecture and scope
- Note any inconsistencies between stated objectives and actual implementation
- Highlight potential supply chain risks from dependencies
- Document the technical foundation that will inform later security analysis
- Consider the maturity and complexity of identified technologies and architectural patterns

Your analysis will be used by subsequent agents for threat modeling, vulnerability analysis, and attack scenario development. Provide actionable technical insights that will inform security assessments.
"""


class TechnicalScopeAgent(BaseThreatAgent):
    """
    A class for handling the creation and management of the technical scope agent
    """

    def __init__(
        self,
        target_path: str = ".",
        model: str = None,
        temperature: float = 0,
    ):
        """
        Initialize the TechnicalScopeAgent.

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
            name="technical_scope_analyst",
        )

    def _initialize_tools(self) -> List[BaseTool]:
        """Initialize tools specific to this agent."""
        code_ingestor_toolkit = create_code_ingestor_toolkit(
            parent_path=self.target_path
        )
        return code_ingestor_toolkit.get_tools()

    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        return TECHNICAL_SCOPE_AGENT_SYSTEM_PROMPT

    def get_agent_node(self):
        """
        Returns a node function that can be added to a StateGraph.

        Returns:
            callable: A function that can be used as a StateGraph node
        """

        def technical_scope_node(state):
            self.logger.info(
                "Starting technical scope analysis", target_path=self.target_path
            )

            try:
                # Access the objectives analysis
                objectives_analysis = state.get("objectives_analysis", "")

                self.logger.debug(
                    "Retrieved objectives analysis from state",
                    has_objectives=bool(objectives_analysis),
                )

                # Build the content message including the objectives analysis
                content_parts = ["Please analyze the technical scope of the codebase."]

                if objectives_analysis:
                    content_parts.append(
                        f"\n<objectives_analysis>\n{objectives_analysis}\n</objectives_analysis>"
                    )
                    content_parts.append(
                        "\nPlease use this analysis as context for your technical scope assessment."
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

                self.logger.debug("Invoking technical scope analysis agent")
                # Invoke the agent
                response = self.agent.invoke({"messages": messages})

                # Extract the analysis content from the agent's response
                # The response["messages"][-1] is an AIMessage object, so we access .content directly
                analysis_content = response["messages"][-1].content

                self.logger.info(
                    "Technical scope analysis completed successfully",
                    response_length=len(analysis_content),
                )

                # Return the analysis directly as a string
                return {"technical_scope": analysis_content}

            except Exception as e:
                self.logger.error(
                    "Error during technical scope analysis",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                raise

        return technical_scope_node
