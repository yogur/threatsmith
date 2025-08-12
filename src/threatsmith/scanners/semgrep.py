import json
import subprocess
from pathlib import Path
from typing import Dict, Any

from threatsmith.utils.logging import get_logger


class SemgrepScannerError(Exception):
    """Custom exception for Semgrep scanner related errors."""

    pass


class SemgrepScanner:
    """Simple wrapper around the Semgrep scanner tool."""

    def __init__(self):
        """Initialize the Semgrep scanner wrapper."""
        self.logger = get_logger("semgrep_scanner")

    def _validate_path(self, path: str) -> Path:
        """
        Validate that the provided path exists and is a directory.

        Args:
            path: The path to validate

        Returns:
            Path: Validated Path object

        Raises:
            SemgrepScannerError: If the path is invalid
        """
        if not path or not isinstance(path, str):
            raise SemgrepScannerError("Path must be a non-empty string")

        try:
            path_obj = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise SemgrepScannerError(f"Invalid path: {e}")

        if not path_obj.exists():
            raise SemgrepScannerError(f"Path does not exist: {path_obj}")

        if not path_obj.is_dir():
            raise SemgrepScannerError(f"Path must be a directory: {path_obj}")

        return path_obj

    def scan(self, target_path: str, config: str = "auto") -> Dict[str, Any]:
        """
        Perform vulnerability scan on the specified path using Semgrep.

        Args:
            target_path: Path to the directory to scan
            config: Semgrep configuration to use (default: "auto")

        Returns:
            Dict: JSON-formatted scan results

        Raises:
            SemgrepScannerError: If scanning fails
        """
        self.logger.debug("Semgrep scan called", target_path=target_path, config=config)

        # Validate input path
        validated_path = self._validate_path(target_path)

        # Build Semgrep command
        cmd = [
            "semgrep",
            "scan",
            "--config",
            config,
            "--severity=ERROR",
            # "--severity=CRITICAL",
            "--json",
            "--quiet",
            "--no-error",  # Don't exit with error code on findings
            str(validated_path),
        ]

        try:
            self.logger.debug("Running Semgrep command", cmd=" ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Semgrep returns various exit codes, but we handle them gracefully
            if result.returncode not in [
                0,
                1,
                2,
            ]:  # 0=no findings, 1=findings, 2=errors but partial results
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                self.logger.error(
                    "Semgrep scanner failed",
                    return_code=result.returncode,
                    error=error_msg,
                )
                raise SemgrepScannerError(f"Semgrep scanner failed: {error_msg}")

            # Parse and return JSON output
            if not result.stdout.strip():
                self.logger.debug("Semgrep scan completed", findings_count=0)
                return {"results": []}

            result_data = json.loads(result.stdout)
            findings_count = len(result_data.get("results", []))
            self.logger.debug("Semgrep scan completed", findings_count=findings_count)
            return result_data

        except subprocess.TimeoutExpired:
            self.logger.error("Semgrep scanner timed out", target_path=target_path)
            raise SemgrepScannerError("Semgrep scanner timed out")
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON output from Semgrep", error=str(e))
            raise SemgrepScannerError(f"Invalid JSON output: {e}")
        except subprocess.SubprocessError as e:
            self.logger.error("Failed to run Semgrep scanner", error=str(e))
            raise SemgrepScannerError(f"Failed to run Semgrep scanner: {e}")


# Convenience function for direct usage
def semgrep_scan_directory(target_path: str, config: str = "auto") -> Dict[str, Any]:
    """
    Convenience function to scan a directory with Semgrep scanner.

    Args:
        target_path: Path to the directory to scan
        config: Semgrep configuration to use (default: "auto")

    Returns:
        Dict: JSON-formatted scan results

    Raises:
        SemgrepScannerError: If scanning fails
    """
    logger = get_logger("semgrep_scanner")
    logger.debug(
        "semgrep_scan_directory called", target_path=target_path, config=config
    )

    scanner = SemgrepScanner()
    result = scanner.scan(target_path, config)

    findings_count = len(result.get("results", []))
    logger.debug(
        "semgrep_scan_directory returning result", findings_count=findings_count
    )
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python semgrep.py <path_to_scan> [config]")
        sys.exit(1)

    target = sys.argv[1]
    config = sys.argv[2] if len(sys.argv) > 2 else "auto"

    try:
        results = semgrep_scan_directory(target, config)
        print(json.dumps(results, indent=2))
    except SemgrepScannerError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
