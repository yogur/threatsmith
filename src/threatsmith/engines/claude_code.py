import logging
import subprocess

from threatsmith.engines.base import Engine

logger = logging.getLogger(__name__)


class ClaudeCodeEngine(Engine):
    def execute(
        self,
        prompt: str,
        working_directory: str,
    ) -> int:
        """Invoke claude CLI in non-interactive prompt mode and return its exit code."""
        cmd = ["claude", "-p", prompt]
        logger.debug("Running: claude -p <prompt> in %s", working_directory)
        result = subprocess.run(cmd, cwd=working_directory)
        return result.returncode
