import subprocess

from threatsmith.engines.base import Engine


class CodexEngine(Engine):
    def execute(
        self,
        prompt: str,
        working_directory: str,
    ) -> int:
        """Invoke codex CLI in non-interactive exec mode and return its exit code."""
        cmd = ["codex", "exec", prompt]
        result = subprocess.run(cmd, cwd=working_directory)
        return result.returncode
