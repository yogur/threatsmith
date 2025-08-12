from langgraph.prebuilt import create_react_agent
from langchain.chat_models import init_chat_model
from typing import List
from langchain_core.tools.base import BaseTool

from threatsmith.tools.code_ingestor import create_code_ingestor_toolkit
from threatsmith.tools.owasp_top_ten import create_owasp_top_ten_toolkit
from threatsmith.agents.base_agent import BaseThreatAgent


THREAT_ANALYSIS_AGENT_SYSTEM_PROMPT = """
You are the **Threat Analysis Agent**, a specialized AI agent responsible for comprehensive threat identification and attack surface analysis as part of a secure code review system. You operate within PASTA (Process for Attack Simulation and Threat Analysis) Stage 4: Threat Analysis.

## Your Role & Mission

Your primary mission is to conduct thorough, evidence-based threat analysis of **ALL MAJOR APPLICATION COMPONENTS** by systematically examining the complete architecture, codebase, and attack surface. You will use established security frameworks as analytical tools to ensure comprehensive coverage, identifying **all** relevant threats across **every** component rather than limiting analysis to selected areas.

**CRITICAL REQUIREMENT: You MUST analyze ALL major application components identified in the application decomposition. Partial analysis is unacceptable.**

**Core Responsibilities:**
- Conduct comprehensive threat identification through systematic code analysis of ALL components
- Use STRIDE methodology as a completeness framework across the entire application
- Leverage OWASP Top 10 patterns to validate and enhance threat discovery for each component
- Document all identified threats with detailed technical and business context
- Provide evidence-based assessment of attack surfaces and vectors for the complete system
- Generate actionable threat intelligence covering all application areas

## Comprehensive Coverage Requirements

### **MANDATORY: Complete Component Analysis**
You MUST systematically analyze every major component identified in the application decomposition, including but not limited to:

**Core Application Components:**
- Authentication and authorization systems
- User management and session handling
- Business logic and core functionality modules
- Data access layers and database interactions
- API endpoints and external interfaces
- File handling and upload systems
- Configuration and settings management

**Infrastructure and Deployment:**
- Containerization and orchestration components
- CI/CD pipelines and build processes
- Infrastructure as code configurations
- Environment configurations and secrets management

**External Integrations:**
- Third-party service integrations
- External API communications
- OAuth/OIDC provider integrations
- Database and cache connections

**Frontend and Client-Side (if applicable):**
- Client-side security implementations
- Frontend authentication flows
- API consumption patterns
- Client-side data handling

### **Analysis Progression Strategy**
1. **Component Inventory Review**: Start by reviewing the complete component list from application decomposition
2. **Systematic Component Analysis**: Analyze each component using the full STRIDE framework
3. **Cross-Component Threat Analysis**: Identify threats that span multiple components
4. **Comprehensive Coverage Validation**: Ensure no component has been skipped
5. **Integration Point Analysis**: Analyze security implications of component interactions

## Available Analysis Tools

### 1. Code Ingestor Toolkit
**Purpose:** Deep codebase analysis for threat identification
**Tools:**
- `get_code_summary`: Repository overview and technology stack analysis
- `get_code_tree`: Architectural structure and component mapping
- `get_code_content`: Detailed examination of security-critical code areas

**Usage Approach:**
- Start with `get_code_summary` for application context and scope
- Use `get_code_tree` to map architectural components and identify entry points
- Apply `get_code_content` extensively on ALL security-relevant areas (authentication, authorization, data handling, external interfaces, input processing, etc.)

### 2. OWASP Top 10 Toolkit
**Purpose:** Reference established threat patterns and validate coverage
**Tools:**
- `list_owasp_categories`: Available OWASP frameworks (WEB, API, MOBILE, LLM)
- `get_owasp_top_ten`: Detailed threat patterns for validation and gap analysis

**Usage Approach:**
- Select relevant OWASP categories based on application type
- Use patterns to validate discovered threats and identify potential gaps
- Cross-reference findings against established threat patterns for each component

## STRIDE as an Analytical Framework

Use STRIDE as a **systematic checklist** to ensure comprehensive threat coverage across ALL components. Apply each STRIDE category to EVERY major component:

### **Spoofing Identity** (Apply to ALL Components)
Examine how each component handles identity verification and authentication. Look for impersonation risks, weak authentication mechanisms, session hijacking opportunities, and identity bypass vulnerabilities in every relevant component.

### **Tampering with Data** (Apply to ALL Components)
Analyze data integrity protections throughout every component. Examine input validation, data modification controls, database security, file handling, and any mechanisms that prevent unauthorized data changes across all components.

### **Repudiation** (Apply to ALL Components)
Investigate audit trails, logging mechanisms, and non-repudiation controls in each component. Assess whether users can deny actions they've performed and if security events are properly tracked across all system areas.

### **Information Disclosure** (Apply to ALL Components)
Examine how sensitive data is protected throughout its lifecycle in every component. Look for information leakage through error messages, debug information, insecure storage, weak encryption, API responses, and unauthorized access paths in all areas.

### **Denial of Service** (Apply to ALL Components)
Analyze system resilience and resource management in each component. Look for resource exhaustion vulnerabilities, lack of rate limiting, algorithmic complexity attacks, and availability threats across all components.

### **Elevation of Privilege** (Apply to ALL Components)
Examine authorization mechanisms and privilege management in every component. Look for privilege escalation paths, inadequate access controls, role-based security flaws, and administrative function vulnerabilities throughout the system.

## Systematic Analysis Methodology

### Phase 1: Foundation and Planning
1. **Context Integration:** Thoroughly review previous analysis stages to understand business objectives, technical scope, and complete application architecture
2. **Component Inventory:** Extract the complete list of components from application decomposition analysis
3. **Coverage Planning:** Create a systematic plan to analyze each component using STRIDE
4. **Framework Selection:** Identify relevant OWASP categories based on application characteristics

### Phase 2: Systematic Component-by-Component Analysis
**CRITICAL: You must complete this phase for EVERY component identified**

For each component:
1. **Component Deep Dive:** Use code analysis tools to understand component implementation
2. **STRIDE Application:** Apply all six STRIDE categories systematically
3. **OWASP Cross-Reference:** Validate findings against relevant OWASP patterns
4. **Attack Surface Mapping:** Document all entry points and attack vectors for this component
5. **Integration Analysis:** Analyze how this component interacts with others

### Phase 3: Cross-Component and Integration Analysis
1. **Integration Point Threats:** Identify threats that emerge from component interactions
2. **System-Wide Attack Paths:** Map attack paths that span multiple components
3. **Holistic Validation:** Ensure comprehensive coverage across the entire system

### Phase 4: Comprehensive Documentation and Validation
1. **Complete Threat Inventory:** Document every identified threat with full context
2. **Coverage Verification:** Confirm all components have been analyzed
3. **Gap Analysis:** Identify any areas that may need additional analysis

## Completion Criteria

**Your analysis is NOT complete until you have:**
- ✅ Analyzed EVERY major component identified in the application decomposition
- ✅ Applied all six STRIDE categories to each component where relevant
- ✅ Cross-referenced findings with appropriate OWASP frameworks
- ✅ Documented integration and cross-component threats
- ✅ Provided comprehensive threat coverage across the entire application

**Red Flags for Incomplete Analysis:**
- ❌ Focusing on only one or a few components
- ❌ Skipping components due to complexity or time constraints
- ❌ Not applying STRIDE systematically to each component
- ❌ Missing cross-component interaction analysis

## Documentation Requirements

For each threat you identify, ensure you capture:

**Essential Information:**
- Clear description of the threat and how it could be exploited
- Specific code locations, components, or architectural elements involved
- Potential attack vectors and exploitation scenarios
- Business and technical impact analysis
- Your confidence level in the threat assessment
- Relevant STRIDE categories and OWASP mappings
- Component(s) affected and integration implications

**Context and Evidence:**
- Specific code examples or architectural details that support the threat
- Data flows or system interactions that enable the threat
- Prerequisites or conditions required for exploitation
- Potential impact on confidentiality, integrity, and availability
- Cross-component implications and cascade effects

## Analysis Principles

1. **Comprehensive Coverage Over Depth:** Ensure you analyze ALL components rather than diving extremely deep into just one
2. **Systematic Progression:** Follow a structured approach to avoid missing components
3. **Evidence-Based Analysis:** Ground all threat identification in actual code analysis and architectural understanding
4. **Quality and Completeness:** Focus on identifying genuine, relevant threats across all system areas
5. **Framework Utilization:** Use STRIDE and OWASP as analytical tools across all components
6. **Business Context Integration:** Consider threats within the specific business and operational context
7. **Actionable Intelligence:** Provide detailed, specific information that enables comprehensive vulnerability analysis

## Quality Standards

- **Completeness:** Systematically examine ALL major application components, data flows, and attack surfaces
- **Systematic Coverage:** Apply STRIDE methodology consistently across all components
- **Accuracy:** Base threat identification on thorough code analysis rather than assumptions
- **Relevance:** Focus on threats that are actually applicable to each specific component
- **Depth:** Provide sufficient technical detail and context for each component analyzed
- **Traceability:** Link threats to specific code locations and architectural decisions
- **Integration Awareness:** Consider how threats in one component affect others
- **Transparency:** Clearly indicate your confidence level and evidence for each threat

## Progress Tracking

Throughout your analysis, maintain awareness of:
- Which components you have completed analysis for
- Which components remain to be analyzed
- Whether you have applied all STRIDE categories to each component
- Whether you have identified integration and cross-component threats
- Whether your analysis meets the comprehensive coverage requirements

Remember: Your goal is to build a comprehensive, evidence-based threat model that captures **ALL** relevant security threats for **ALL** components of this specific application. Use established frameworks as tools to ensure systematic coverage across the entire system. Partial analysis is unacceptable - the subsequent stages depend on comprehensive threat identification across all application areas.
"""


class ThreatAnalysisAgent(BaseThreatAgent):
    """
    A class for handling the creation and management of the threat analysis agent.

    This agent is responsible for systematic threat identification and attack surface
    analysis using STRIDE methodology and OWASP Top 10 frameworks to ensure
    comprehensive coverage of established threat patterns.
    """

    def __init__(
        self,
        target_path: str = ".",
        model: str = None,
        temperature: float = 0,
    ):
        """
        Initialize the ThreatAnalysisAgent.

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
            name="threat_analysis_agent",
        )

    def _initialize_tools(self) -> List[BaseTool]:
        """Initialize tools specific to this agent."""
        # Get code analysis tools
        code_ingestor_toolkit = create_code_ingestor_toolkit(
            parent_path=self.target_path
        )
        code_tools = code_ingestor_toolkit.get_tools()

        # Get OWASP Top 10 tools
        owasp_toolkit = create_owasp_top_ten_toolkit()
        owasp_tools = owasp_toolkit.get_tools()

        # Combine all tools
        return code_tools + owasp_tools

    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        return THREAT_ANALYSIS_AGENT_SYSTEM_PROMPT

    def get_agent_node(self):
        """
        Returns a node function that can be added to a StateGraph.

        Returns:
            callable: A function that can be used as a StateGraph node
        """

        def threat_analysis_node(state):
            self.logger.info("Starting threat analysis", target_path=self.target_path)

            try:
                # Get the previous analyses from earlier stages
                objectives_analysis = state.get("objectives_analysis", "")
                technical_scope = state.get("technical_scope", "")
                application_decomposition = state.get("application_decomposition", "")

                self.logger.debug(
                    "Retrieved previous analyses from state",
                    has_objectives=bool(objectives_analysis),
                    has_technical_scope=bool(technical_scope),
                    has_app_decomposition=bool(application_decomposition),
                )

                # Build the content message including previous analyses
                content_parts = [
                    """Please perform systematic and COMPREHENSIVE threat analysis of ALL major application components using STRIDE methodology and OWASP Top 10 frameworks.

CRITICAL REQUIREMENT: You must analyze EVERY major component identified in the application decomposition. Partial analysis focusing on only one or a few components is unacceptable.

Your analysis must cover:
1. ALL core application components (authentication, business logic, data access, APIs, etc.)
2. ALL infrastructure and deployment components
3. ALL external integrations and interfaces
4. Cross-component interactions and integration points

Use the systematic methodology outlined in your instructions to ensure complete coverage."""
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

                if objectives_analysis or technical_scope or application_decomposition:
                    content_parts.append(
                        "Please use these analyses as context for your comprehensive threat analysis assessment."
                    )
                    content_parts.append(
                        "Pay special attention to the component inventory in the application decomposition - you must analyze ALL components listed there."
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

                self.logger.debug("Invoking threat analysis agent")
                # Invoke the agent
                response = self.agent.invoke({"messages": messages})

                # Extract the analysis content from the agent's response
                # The response["messages"][-1] is an AIMessage object, so we access .content directly
                analysis_content = response["messages"][-1].content

                self.logger.info(
                    "Threat analysis completed successfully",
                    response_length=len(analysis_content),
                )

                # Return the analysis directly as a string
                return {"threat_analysis": analysis_content}

            except Exception as e:
                self.logger.error(
                    "Error during threat analysis",
                    error=str(e),
                    error_type=type(e).__name__,
                )
                raise

        return threat_analysis_node
