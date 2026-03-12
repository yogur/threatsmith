from abc import ABC, abstractmethod


class Engine(ABC):
    @abstractmethod
    def execute(
        self,
        prompt: str,
        working_directory: str,
    ) -> int:
        """Execute the engine with the assembled prompt and return an exit code."""
        ...
