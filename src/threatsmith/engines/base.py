from abc import ABC, abstractmethod
from pathlib import Path


class Engine(ABC):
    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

    @property
    @abstractmethod
    def skills_dir(self) -> Path:
        """Directory where this engine loads personally-installed skills.

        Used by ``threatsmith skills install`` to choose where to copy the
        bundled skills so the selected engine can load them.
        """
        ...

    @abstractmethod
    def execute(
        self,
        prompt: str,
        working_directory: str,
        output_dir: str,
    ) -> int:
        """Execute the engine with the assembled prompt and return an exit code."""
        ...
