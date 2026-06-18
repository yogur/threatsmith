from abc import ABC, abstractmethod


class Engine(ABC):
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    @abstractmethod
    def execute(
        self,
        prompt: str,
        working_directory: str,
        output_dir: str,
    ) -> int:
        """Execute the engine with the assembled prompt and return an exit code."""
        ...
