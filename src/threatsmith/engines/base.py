from abc import ABC, abstractmethod


class Engine(ABC):
    @abstractmethod
    def execute(
        self,
        system_prompt: str,
        user_prompt: str,
        working_directory: str,
        allowed_tools: list[str] | None = None,
    ) -> int:
        """Execute the engine with the given prompts and return an exit code."""
        ...
