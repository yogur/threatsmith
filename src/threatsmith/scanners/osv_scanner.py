import json
import subprocess
from pathlib import Path
from typing import Dict, Any

from threatsmith.utils.logging import get_logger


class OSVScannerError(Exception):
    """Custom exception for OSV scanner related errors."""

    pass


class OSVScanner:
    """Simple wrapper around the OSV scanner tool."""

    def __init__(self):
        """Initialize the OSV scanner wrapper."""
        self.logger = get_logger("osv_scanner")

    def _validate_path(self, path: str) -> Path:
        """
        Validate that the provided path exists and is a directory.

        Args:
            path: The path to validate

        Returns:
            Path: Validated Path object

        Raises:
            OSVScannerError: If the path is invalid
        """
        if not path or not isinstance(path, str):
            raise OSVScannerError("Path must be a non-empty string")

        try:
            path_obj = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise OSVScannerError(f"Invalid path: {e}")

        if not path_obj.exists():
            raise OSVScannerError(f"Path does not exist: {path_obj}")

        if not path_obj.is_dir():
            raise OSVScannerError(f"Path must be a directory: {path_obj}")

        return path_obj

    def scan(self, target_path: str) -> Dict[str, Any]:
        """
        Perform vulnerability scan on the specified path.

        Args:
            target_path: Path to the directory to scan

        Returns:
            Dict: JSON-formatted scan results

        Raises:
            OSVScannerError: If scanning fails
        """
        self.logger.debug("OSV scan called", target_path=target_path)

        # Validate input path
        validated_path = self._validate_path(target_path)

        # Run OSV scanner
        cmd = [
            "osv-scanner",
            "scan",
            "source",
            "--format",
            "json",
            "--verbosity",
            "error",
            "-r",
            str(validated_path),
        ]

        try:
            self.logger.debug("Running OSV command", cmd=" ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # OSV scanner returns 0 (no vulns) or 1 (vulns found) - both are success
            if result.returncode not in [0, 1]:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                self.logger.error(
                    "OSV scanner failed", return_code=result.returncode, error=error_msg
                )
                raise OSVScannerError(f"OSV scanner failed: {error_msg}")

            # Parse and return JSON output
            if not result.stdout.strip():
                self.logger.debug("OSV scan completed", findings_count=0)
                return {}

            result_data = json.loads(result.stdout)
            findings_count = len(result_data.get("results", []))
            self.logger.debug("OSV scan completed", findings_count=findings_count)
            return result_data

        except subprocess.TimeoutExpired:
            self.logger.error("OSV scanner timed out", target_path=target_path)
            raise OSVScannerError("OSV scanner timed out")
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON output from OSV", error=str(e))
            raise OSVScannerError(f"Invalid JSON output: {e}")
        except subprocess.SubprocessError as e:
            self.logger.error("Failed to run OSV scanner", error=str(e))
            raise OSVScannerError(f"Failed to run OSV scanner: {e}")


# Convenience function for direct usage
def osv_scan_directory(target_path: str) -> Dict[str, Any]:
    """
    Convenience function to scan a directory with OSV scanner.

    Args:
        target_path: Path to the directory to scan

    Returns:
        Dict: JSON-formatted scan results

    Raises:
        OSVScannerError: If scanning fails
    """
    logger = get_logger("osv_scanner")
    logger.debug("osv_scan_directory called", target_path=target_path)

    scanner = OSVScanner()
    result = scanner.scan(target_path)

    findings_count = len(result.get("results", []))
    logger.debug("osv_scan_directory returning result", findings_count=findings_count)
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python osv_scanner.py <path_to_scan>")
        sys.exit(1)

    try:
        results = osv_scan_directory(sys.argv[1])
        print(json.dumps(results, indent=2))
    except OSVScannerError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
