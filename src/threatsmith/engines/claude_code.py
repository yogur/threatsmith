import json
import logging
import subprocess

from threatsmith.engines.base import Engine

logger = logging.getLogger(__name__)

_SCANNER_PERMISSIONS: dict[str, str] = {
    "semgrep": "Bash(semgrep *)",
    "trivy": "Bash(trivy *)",
    "gitleaks": "Bash(gitleaks *)",
}

_ENGINE_CONSTRAINTS = """

## ENGINE CONSTRAINTS

You have full read access to the repository via your built-in file tools (Read, Grep, Glob).
You can write and edit files in the output directory.
You can run the security scanner commands specified in the prompt instructions.
For any analysis that would typically require running scripts or interpreters, use your \
reasoning capabilities directly instead.
"""


class ClaudeCodeEngine(Engine):
    def execute(
        self,
        prompt: str,
        working_directory: str,
        output_dir: str,
    ) -> int:
        """Invoke claude CLI in non-interactive prompt mode and return its exit code."""
        safe_dir = output_dir.rstrip("/")
        allowed_tools = [f"Write({safe_dir}/**)", f"Edit({safe_dir}/**)"]
        if self.scanner_names:
            for name in self.scanner_names:
                perm = _SCANNER_PERMISSIONS.get(name)
                if perm:
                    allowed_tools.append(perm)

        full_prompt = prompt + _ENGINE_CONSTRAINTS

        cmd = [
            "claude",
            "-p",
            full_prompt,
            "--allowedTools",
            *allowed_tools,
        ]
        logger.debug("Running: claude -p <prompt> in %s", working_directory)
        try:
            if self.verbose:
                return self._execute_verbose(cmd, working_directory)
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

    def _execute_verbose(self, cmd: list[str], working_directory: str) -> int:
        """Run claude with stream-json output, printing text deltas as they arrive."""
        verbose_cmd = cmd + [
            "--verbose",
            "--output-format",
            "stream-json",
            "--include-partial-messages",
        ]
        proc = subprocess.Popen(
            verbose_cmd, cwd=working_directory, stdout=subprocess.PIPE, text=True
        )
        for line in proc.stdout:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                obj.get("type") == "stream_event"
                and obj.get("event", {}).get("delta", {}).get("type") == "text_delta"
            ):
                print(obj["event"]["delta"]["text"], end="", flush=True)
        proc.wait()
        print()  # newline after streaming completes
        return proc.returncode
