from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model
from typing import List
from langchain_core.tools.base import BaseTool

from threatsmith.agents.base_agent import BaseThreatAgent


REPORTING_AGENT_SYSTEM_PROMPT = """
You are the Enhanced Reporting Agent, responsible for consolidating the analysis outputs from all previous security analysis agents into a comprehensive, cohesive threat analysis report.

## Core Responsibilities

1. **Consolidate and Format**: Combine analysis outputs from all 6 sub-agents into a unified, professional report
2. **Preserve Accuracy**: Do NOT alter, modify, or reinterpret any facts, findings, or analysis conclusions from the sub-agents
3. **Filter Content**: Remove conversational elements, questions, and agent-to-agent communication from outputs
4. **Structure Information**: Organize content logically with clear sections and subsections
5. **Embed Visuals**: Properly integrate any Mermaid diagrams as code blocks within the report

## Input Analysis Outputs

You will receive the following analysis outputs to consolidate:

- **objectives_analysis**: Business context, data sensitivity, and compliance requirements
- **technical_scope**: Technology stack, dependencies, and infrastructure overview  
- **application_decomposition**: Application architecture, entry points, and data flows
- **threat_analysis**: STRIDE-based threat model and attack surface analysis
- **vulnerability_analysis**: Specific vulnerabilities with CVSS scoring and remediation guidance
- **attack_modeling**: Attack scenarios, exploitation paths, and impact assessments

## Report Organization

Generate a comprehensive security analysis report with flexible organization that preserves the complete output from each agent:

### Executive Summary
Create a concise executive summary that consolidates:
- High-level security posture overview
- Critical findings requiring immediate attention  
- Key risk areas and technical priorities
- Summary of major threats, vulnerabilities, and attack scenarios
- Clear separation between technical risk and business prioritization needs

### Agent Analysis Sections (Preserve Complete Output)
Present each agent's analysis in logical order, preserving their complete narrative output:

1. **Application Objectives & Context** - Complete output from objectives analysis
2. **Technical Architecture & Scope** - Complete output from technical scope analysis  
3. **Application Structure & Decomposition** - Complete output from application decomposition analysis
4. **Threat Analysis & Attack Surface** - Complete output from threat analysis
5. **Vulnerability Assessment** - Complete output from vulnerability analysis
6. **Attack Modeling & Scenarios** - Complete output from attack modeling analysis

### Conclusion (Optional)
If valuable insights emerge from consolidating all analyses, provide a brief conclusion that:
- Highlights the overall security posture
- Notes any recurring themes or patterns across analyses
- Provides final guidance for prioritization and next steps

## Content Processing Guidelines

### Filtering Rules
- Remove any conversational questions like "What would you like me to focus on?" or "Should I analyze X or Y?"
- Filter out agent-to-agent communication or meta-commentary
- Remove prompting language like "I notice..." or "I recommend we..."
- Exclude any uncertainty expressions or requests for clarification

### Mermaid Diagram Integration
- When encountering Mermaid diagrams in sub-agent outputs, embed them as proper code blocks:
```mermaid
[diagram content]
```
- Ensure diagrams are properly formatted and syntactically correct
- Include diagram titles and descriptions where provided
- Maintain visual hierarchy and readability

### Content Preservation
- Preserve all technical findings, CVSS scores, and risk assessments exactly as provided
- Maintain vulnerability descriptions, attack scenarios, and remediation guidance without modification
- Keep all specific code references, file paths, and technical details intact
- Preserve scanner results and tool outputs accurately

### Risk Assessment Preservation
- Preserve the complete risk assessments from vulnerability analysis (Agent 5) and attack modeling (Agent 6) without modification
- Maintain the CVSS scoring, impact assessments, and technical risk evaluations exactly as provided
- Preserve any existing risk matrices or prioritization frameworks included in agent outputs
- Maintain the clear separation between technical risk assessment and business prioritization that agents established
- Do not create new risk assessments or modify existing ones - simply preserve and present them clearly

## Output Requirements

- Generate ONLY the consolidated report content
- **PRESERVE COMPLETE AGENT OUTPUTS**: Present each agent's full analysis without truncation, alteration, or restructuring
- Use professional, technical language appropriate for security stakeholders
- Maintain the natural narrative flow and structure that each agent produced
- Ensure proper markdown formatting with clear section headings
- **FILTER ONLY**: Remove conversational elements, questions, and agent-to-agent communication
- **DO NOT RESTRUCTURE**: Avoid forcing agent outputs into rigid templates or categories
- Do NOT include any conversational elements, questions, or requests for feedback
- Do NOT add your own analysis or interpretations beyond what was provided by sub-agents
- Focus on consolidation and organization rather than reformatting or summarizing

## Quality Standards

- **Complete Preservation**: Maintain the comprehensive coverage and rich context from each agent's analysis
- **Natural Organization**: Present analyses in logical order while preserving their organic narrative structure  
- **Content Fidelity**: Accurately preserve all technical findings, recommendations, and insights without alteration
- **Professional Filtering**: Remove only conversational elements while maintaining the professional tone each agent established
- **Integrated Flow**: Create seamless transitions between agent sections using minimal bridging text when necessary
- **Visual Integrity**: Properly embed all Mermaid diagrams and visual elements as they were intended

Your output should be a complete, standalone security analysis report that preserves the depth and expertise of each specialized agent while presenting it as a cohesive, professional document for security engineers, development teams, and stakeholders.
"""


class ReportingAgent(BaseThreatAgent):
    """
    A class for handling the creation and management of the reporting agent.

    This agent is responsible for consolidating analysis outputs from all previous
    security analysis agents into a comprehensive, cohesive threat analysis report.
    """

    def __init__(
        self,
        target_path: str = ".",
        model: str = None,
        temperature: float = 0,
    ):
        """
        Initialize the ReportingAgent.

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
            name="reporting_agent",
        )

    def _initialize_tools(self) -> List[BaseTool]:
        """Initialize tools specific to this agent."""
        # Reporting agent doesn't need any tools - it only consolidates
        # outputs from previous agents
        return []

    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        return REPORTING_AGENT_SYSTEM_PROMPT

    def get_agent_node(self):
        """
        Returns a node function that can be added to a StateGraph.

        Returns:
            callable: A function that can be used as a StateGraph node
        """

        def reporting_node(state):
            self.logger.info(
                "Starting final report generation", target_path=self.target_path
            )

            try:
                # Get all previous analyses from earlier stages
                objectives_analysis = state.get("objectives_analysis", "")
                technical_scope = state.get("technical_scope", "")
                application_decomposition = state.get("application_decomposition", "")
                threat_analysis = state.get("threat_analysis", "")
                vulnerability_analysis = state.get("vulnerability_analysis", "")
                attack_modeling = state.get("attack_modeling", "")

                self.logger.debug(
                    "Retrieved all previous analyses from state",
                    has_objectives=bool(objectives_analysis),
                    has_technical_scope=bool(technical_scope),
                    has_app_decomposition=bool(application_decomposition),
                    has_threat_analysis=bool(threat_analysis),
                    has_vulnerability_analysis=bool(vulnerability_analysis),
                    has_attack_modeling=bool(attack_modeling),
                )

                # Build the content message including all previous analyses
                content_parts = [
                    """Please consolidate the analysis outputs from all previous security analysis agents into a comprehensive, cohesive threat analysis report.

Your task is to:
1. Create a concise executive summary highlighting critical findings
2. Present each agent's complete analysis in logical order without alteration
3. Filter out conversational elements while preserving all technical content
4. Properly format any Mermaid diagrams as code blocks
5. Generate a professional, standalone security analysis report

Preserve all technical findings, CVSS scores, risk assessments, and recommendations exactly as provided by the specialized agents."""
                ]

                if objectives_analysis:
                    content_parts.append(
                        f"<objectives_analysis>\n{objectives_analysis}\n</objectives_analysis>"
                    )

                if technical_scope:
                    content_parts.append(
                        f"<technical_scope>\n{technical_scope}\n</technical_scope>"
                    )

                if application_decomposition:
                    content_parts.append(
                        f"<application_decomposition>\n{application_decomposition}\n</application_decomposition>"
                    )

                if threat_analysis:
                    content_parts.append(
                        f"<threat_analysis>\n{threat_analysis}\n</threat_analysis>"
                    )

                if vulnerability_analysis:
                    content_parts.append(
                        f"<vulnerability_analysis>\n{vulnerability_analysis}\n</vulnerability_analysis>"
                    )

                if attack_modeling:
                    content_parts.append(
                        f"<attack_modeling>\n{attack_modeling}\n</attack_modeling>"
                    )

                if any(
                    [
                        objectives_analysis,
                        technical_scope,
                        application_decomposition,
                        threat_analysis,
                        vulnerability_analysis,
                        attack_modeling,
                    ]
                ):
                    content_parts.append(
                        "Please use these analyses as the complete source material for your consolidated security analysis report."
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

                self.logger.debug("Invoking reporting agent")
                # Invoke the agent
                response = self.agent.invoke({"messages": messages})

                # Extract the analysis content from the agent's response
                # The response["messages"][-1] is an AIMessage object, so we access .content directly
                analysis_content = response["messages"][-1].content

                self.logger.info(
                    "Final report generation completed successfully",
                    response_length=len(analysis_content),
                )

                # Return the analysis directly as a string
                return {"final_report": analysis_content}

            except Exception as e:
                self.logger.error(
                    "Error during final report generation",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                raise

        return reporting_node
