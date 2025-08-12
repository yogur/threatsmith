"""
Base agent class providing common interface for all ThreatSmith agents.

This class defines the interface that all threat analysis agents must implement.
It provides a common structure for agents to follow, ensuring consistency
and interoperability across different threat analysis tasks.
"""

from abc import ABC, abstractmethod
from typing import Any, List
from langchain_core.tools.base import BaseTool

from threatsmith.utils.logging import get_logger


class BaseThreatAgent(ABC):
    """Abstract base class for all threat analysis agents."""

    def __init__(self, target_path: str, model: str, temperature: float):
        self.target_path = target_path
        self.model = model
        self.temperature = temperature
        self.logger = get_logger(self.__class__.__name__)
        self.tools = self._initialize_tools()

    @abstractmethod
    def _initialize_tools(self) -> List[BaseTool]:
        """Initialize tools specific to this agent."""
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent."""
        pass

    @abstractmethod
    def get_agent_node(self) -> Any:
        """Get the LangGraph node for this agent."""
        pass

    # @abstractmethod
    # def process_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
    #     """Process and structure the agent's results."""
    #     pass
