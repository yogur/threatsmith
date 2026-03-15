import logging
import subprocess

from threatsmith.engines.base import Engine

logger = logging.getLogger(__name__)


class CodexEngine(Engine):
    def execute(
        self,
        prompt: str,
        working_directory: str,
        output_dir: str,
    ) -> int:
        """Invoke codex CLI in non-interactive exec mode and return its exit code."""
        cmd = ["codex", "exec", prompt]
        logger.debug("Running: codex exec <prompt> in %s", working_directory)
        try:
            result = subprocess.run(cmd, cwd=working_directory)
            return result.returncode
        except FileNotFoundError:
            logger.error(
                "Codex CLI not found. Ensure 'codex' is installed and in your PATH."
            )
            return 1
        except Exception as e:
            logger.error("Error executing codex: %s", str(e))
            return 1
