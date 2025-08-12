from typing import Optional, TypedDict
from pathlib import Path
from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph

from threatsmith.utils.logging import get_logger
from threatsmith.agents.objectives_agent import ObjectivesAgent
from threatsmith.agents.technical_scope_agent import TechnicalScopeAgent
from threatsmith.agents.application_decomposition_agent import (
    ApplicationDecompositionAgent,
)
from threatsmith.agents.threat_analysis_agent import ThreatAnalysisAgent
from threatsmith.agents.vulnerability_analysis_agent import VulnerabilityAnalysisAgent
from threatsmith.agents.attack_modeling_agent import AttackModelingAgent
from threatsmith.agents.reporting_agent import ReportingAgent
from threatsmith.utils.reporting import ThreatAnalysisReporter


class ThreatAnalysisState(TypedDict):
    """
    State for the complete threat analysis process with 7 agents.
    Each agent has dedicated output fields to maintain clear separation of concerns.
    Agent 7 (Risk & Impact Analysis) has been removed to avoid redundancy with
    comprehensive risk assessment already integrated into Agents 5 and 6.
    """

    # Initial input parameters
    target_path: str
    business_objectives: Optional[str]
    security_objectives: Optional[str]

    # Agent outputs - simplified to strings for single-pass analysis
    objectives_analysis: str  # Stage 1: Define Objectives
    technical_scope: str  # Stage 2: Define Technical Scope
    application_decomposition: str  # Stage 3: Application Decomposition
    threat_analysis: str  # Stage 4: Threat Analysis
    vulnerability_analysis: str  # Stage 5: Vulnerability Analysis
    attack_modeling: str  # Stage 6: Attack Modeling
    final_report: str  # Stage 7: Enhanced Reporting


class AnalysisResults:
    """Container for analysis results with methods to save and format output."""

    def __init__(self, results: dict, output_dir: Path):
        self.results = results
        self.output_dir = output_dir
        self.reporter = ThreatAnalysisReporter(output_dir)

    @classmethod
    def from_graph_results(cls, results: dict, output_dir: Path) -> "AnalysisResults":
        """Create AnalysisResults from graph execution results."""
        return cls(results, output_dir)

    def save_results(self, save_stage_outputs: bool = False) -> dict:
        """Save results in the specified format(s)."""
        saved_files = self.reporter.save_results(
            state=self.results, save_stage_outputs=save_stage_outputs
        )

        return saved_files


class ThreatAnalysisOrchestrator:
    """Orchestrates the 7-stage PASTA threat analysis process."""

    def __init__(self, target_path: Path, model: str, output_dir: Path):
        self.target_path = target_path
        self.model = model
        self.output_dir = output_dir
        self.logger = get_logger(__name__)
        self.graph = self._create_analysis_graph()

    def _create_analysis_graph(self) -> CompiledStateGraph:
        """Create the complete 7-agent analysis graph."""
        # Initialize agents
        objectives_agent = ObjectivesAgent(
            target_path=str(self.target_path), model=self.model
        )
        technical_scope_agent = TechnicalScopeAgent(
            target_path=str(self.target_path), model=self.model
        )
        application_decomposition_agent = ApplicationDecompositionAgent(
            target_path=str(self.target_path), model=self.model
        )
        threat_analysis_agent = ThreatAnalysisAgent(
            target_path=str(self.target_path), model=self.model
        )
        vulnerability_analysis_agent = VulnerabilityAnalysisAgent(
            target_path=str(self.target_path), model=self.model
        )
        attack_modeling_agent = AttackModelingAgent(
            target_path=str(self.target_path), model=self.model
        )
        reporting_agent = ReportingAgent(
            target_path=str(self.target_path), model=self.model
        )

        # Create graph
        graph = StateGraph(ThreatAnalysisState)

        # Add nodes
        graph.add_node("objectives", objectives_agent.get_agent_node())
        graph.add_node("technical_scope", technical_scope_agent.get_agent_node())
        graph.add_node(
            "application_decomposition",
            application_decomposition_agent.get_agent_node(),
        )
        graph.add_node(
            "threat_analysis",
            threat_analysis_agent.get_agent_node(),
        )
        graph.add_node(
            "vulnerability_analysis",
            vulnerability_analysis_agent.get_agent_node(),
        )
        graph.add_node(
            "attack_modeling",
            attack_modeling_agent.get_agent_node(),
        )
        graph.add_node(
            "reporting",
            reporting_agent.get_agent_node(),
        )

        # Define the analysis flow
        graph.add_edge(START, "objectives")
        graph.add_edge("objectives", "technical_scope")
        graph.add_edge("technical_scope", "application_decomposition")
        graph.add_edge("application_decomposition", "threat_analysis")
        graph.add_edge("threat_analysis", "vulnerability_analysis")
        graph.add_edge("vulnerability_analysis", "attack_modeling")
        graph.add_edge("attack_modeling", "reporting")
        graph.add_edge("reporting", END)

        return graph.compile()

    def run_analysis(
        self,
        business_objectives: Optional[str] = None,
        security_objectives: Optional[str] = None,
        save_stage_outputs: bool = False,
    ) -> AnalysisResults:
        """Execute the complete threat analysis pipeline."""

        self.logger.info(
            "Starting threat analysis",
            target_path=str(self.target_path),
            model=self.model,
        )

        # Initialize state
        initial_state = {
            "target_path": str(self.target_path),
            "business_objectives": business_objectives,
            "security_objectives": security_objectives,
            # Initialize all agent outputs as empty strings
            "objectives_analysis": "",
            "technical_scope": "",
            "application_decomposition": "",
            "threat_analysis": "",
            "vulnerability_analysis": "",
            "attack_modeling": "",
            "final_report": "",
        }

        self.logger.debug("Initial state configured", **initial_state)

        # Execute graph
        self.logger.info("Executing analysis pipeline")
        results = self.graph.invoke(initial_state)
        self.logger.info("Analysis pipeline completed successfully")

        # Process and save results
        analysis_results = AnalysisResults.from_graph_results(results, self.output_dir)

        # Save results to markdown file(s)
        saved_files = analysis_results.save_results(save_stage_outputs)

        # Log saved files
        for report_type, filepath in saved_files.items():
            self.logger.info(
                f"{report_type.replace('_', ' ').title()} saved", filepath=filepath
            )

        return analysis_results
