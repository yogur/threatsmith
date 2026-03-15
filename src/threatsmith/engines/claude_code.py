import logging
import subprocess

from threatsmith.engines.base import Engine

logger = logging.getLogger(__name__)


class ClaudeCodeEngine(Engine):
    def execute(
        self,
        prompt: str,
        working_directory: str,
        output_dir: str,
    ) -> int:
        """Invoke claude CLI in non-interactive prompt mode and return its exit code."""
        safe_dir = output_dir.rstrip("/")
        cmd = [
            "claude",
            "-p",
            prompt,
            "--allowedTools",
            f"Write({safe_dir}/**)",
            f"Edit({safe_dir}/**)",
        ]
        logger.debug("Running: claude -p <prompt> in %s", working_directory)
        try:
            result = subprocess.run(cmd, cwd=working_directory)
            return result.returncode
        except FileNotFoundError:
            logger.error(
                "Claude CLI not found. Ensure 'claude' is installed and in your PATH."
            )
            return 1
        except Exception as e:
            logger.error("Error executing claude: %s", str(e))
            return 1
