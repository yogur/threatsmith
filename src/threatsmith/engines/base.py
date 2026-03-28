from abc import ABC, abstractmethod


class Engine(ABC):
    def __init__(
        self, verbose: bool = False, scanner_names: list[str] | None = None
    ) -> None:
        self.verbose = verbose
        self.scanner_names = scanner_names

    @abstractmethod
    def execute(
        self,
        prompt: str,
        working_directory: str,
        output_dir: str,
    ) -> int:
        """Execute the engine with the assembled prompt and return an exit code."""
        ...
