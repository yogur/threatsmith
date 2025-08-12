import json
import subprocess
from pathlib import Path
from typing import Dict, Any

from threatsmith.utils.logging import get_logger


class TrivyScannerError(Exception):
    """Custom exception for Trivy scanner related errors."""

    pass


class TrivyScanner:
    """Simple wrapper around the Trivy filesystem scanner tool."""

    def __init__(self):
        """Initialize the Trivy scanner wrapper."""
        self.logger = get_logger("trivy_scanner")

    def _validate_path(self, path: str) -> Path:
        """
        Validate that the provided path exists and is a directory.

        Args:
            path: The path to validate

        Returns:
            Path: Validated Path object

        Raises:
            TrivyScannerError: If the path is invalid
        """
        if not path or not isinstance(path, str):
            raise TrivyScannerError("Path must be a non-empty string")

        try:
            path_obj = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise TrivyScannerError(f"Invalid path: {e}")

        if not path_obj.exists():
            raise TrivyScannerError(f"Path does not exist: {path_obj}")

        if not path_obj.is_dir():
            raise TrivyScannerError(f"Path must be a directory: {path_obj}")

        return path_obj

    def scan(self, target_path: str, scanner_type: str = "vuln") -> Dict[str, Any]:
        """
        Perform vulnerability scan on the specified path using Trivy.

        Args:
            target_path: Path to the directory to scan

        Returns:
            Dict: JSON-formatted scan results

        Raises:
            TrivyScannerError: If scanning fails
        """
        self.logger.debug(
            "Trivy scan called", target_path=target_path, scanner_type=scanner_type
        )

        # Validate input path
        validated_path = self._validate_path(target_path)

        # Build Trivy command
        cmd = [
            "trivy",
            "fs",
            "--format",
            "json",
            "--severity",
            "CRITICAL,HIGH",
            "--scanners",
            scanner_type,  # Only scan for vulnerabilities (CVEs), not secrets/misconfig/license
            "--quiet",
            "--exit-code",
            "0",  # Don't exit with error code on findings
            "--disable-telemetry",
            str(validated_path),
        ]

        try:
            self.logger.debug("Running Trivy command", cmd=" ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Check for command execution errors
            if result.returncode != 0:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                self.logger.error(
                    "Trivy scanner failed",
                    return_code=result.returncode,
                    error=error_msg,
                )
                raise TrivyScannerError(f"Trivy scanner failed: {error_msg}")

            # Parse and return JSON output
            if not result.stdout.strip():
                self.logger.debug("Trivy scan completed", findings_count=0)
                return {"Results": []}

            result_data = json.loads(result.stdout)
            findings_count = sum(
                len(r.get("Vulnerabilities", []))
                for r in result_data.get("Results", [])
            )
            self.logger.debug("Trivy scan completed", findings_count=findings_count)
            return result_data

        except subprocess.TimeoutExpired:
            self.logger.error("Trivy scanner timed out", target_path=target_path)
            raise TrivyScannerError("Trivy scanner timed out")
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON output from Trivy", error=str(e))
            raise TrivyScannerError(f"Invalid JSON output: {e}")
        except subprocess.SubprocessError as e:
            self.logger.error("Failed to run Trivy scanner", error=str(e))
            raise TrivyScannerError(f"Failed to run Trivy scanner: {e}")


# Convenience function for direct usage
def trivy_scan_directory(
    target_path: str, scanner_type: str = "vuln"
) -> Dict[str, Any]:
    """
    Convenience function to scan a directory with Trivy scanner.

    Args:
        target_path: Path to the directory to scan

    Returns:
        Dict: JSON-formatted scan results

    Raises:
        TrivyScannerError: If scanning fails
    """
    logger = get_logger("trivy_scanner")
    logger.debug(
        "trivy_scan_directory called",
        target_path=target_path,
        scanner_type=scanner_type,
    )

    scanner = TrivyScanner()
    result = scanner.scan(target_path, scanner_type)

    findings_count = sum(
        len(r.get("Vulnerabilities", [])) for r in result.get("Results", [])
    )
    logger.debug("trivy_scan_directory returning result", findings_count=findings_count)
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python trivy.py <path_to_scan>")
        sys.exit(1)

    target = sys.argv[1]

    try:
        results = trivy_scan_directory(target)
        print(json.dumps(results, indent=2))
    except TrivyScannerError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
