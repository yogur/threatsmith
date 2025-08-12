import json
import subprocess
import tempfile
import os
from pathlib import Path
from typing import Dict, Any

from threatsmith.utils.logging import get_logger


class GitleaksError(Exception):
    """Custom exception for Gitleaks scanner related errors."""

    pass


class GitleaksScanner:
    """Simple wrapper around the Gitleaks scanner tool."""

    def __init__(self):
        """Initialize the Gitleaks scanner wrapper."""
        self.logger = get_logger("gitleaks_scanner")

    def _validate_path(self, path: str) -> Path:
        """
        Validate that the provided path exists.

        Args:
            path: The path to validate

        Returns:
            Path: Validated Path object

        Raises:
            GitleaksError: If the path is invalid
        """
        if not path or not isinstance(path, str):
            raise GitleaksError("Path must be a non-empty string")

        try:
            path_obj = Path(path).resolve()
        except (OSError, ValueError) as e:
            raise GitleaksError(f"Invalid path: {e}")

        if not path_obj.exists():
            raise GitleaksError(f"Path does not exist: {path_obj}")

        return path_obj

    def scan(self, target_path: str, config: str = None) -> Dict[str, Any]:
        """
        Perform secrets scan on the specified path using Gitleaks.

        Args:
            target_path: Path to the directory or file to scan
            config: Optional path to custom Gitleaks configuration file

        Returns:
            Dict: JSON-formatted scan results

        Raises:
            GitleaksError: If scanning fails
        """
        self.logger.debug(
            "Gitleaks scan called", target_path=target_path, config=config
        )

        # Validate input path
        validated_path = self._validate_path(target_path)

        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".json", delete=False
        ) as temp_file:
            temp_path = temp_file.name

        try:
            # Build Gitleaks command
            cmd = [
                "gitleaks",
                "dir",
                "--report-format",
                "json",
                "--report-path",
                temp_path,
                "--no-banner",
                "--no-color",
                "--redact=100",  # Fully redact secrets for security
                str(validated_path),
            ]

            # Add config if provided
            if config:
                cmd.extend(["--config", config])

            self.logger.debug("Running Gitleaks command", cmd=" ".join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # Gitleaks returns exit code 1 when secrets are found, 0 when none found
            if result.returncode not in [0, 1]:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                self.logger.error(
                    "Gitleaks scanner failed",
                    return_code=result.returncode,
                    error=error_msg,
                )
                raise GitleaksError(f"Gitleaks scanner failed: {error_msg}")

            # Read and parse JSON output from temporary file
            try:
                with open(temp_path, "r") as f:
                    content = f.read().strip()
                    if not content:
                        result_data = {"results": []}
                        self.logger.debug("Gitleaks scan completed", findings_count=0)
                        return result_data
                    result_data = json.loads(content)

                    # Gitleaks returns a list directly, wrap in standard format
                    findings_count = len(result_data)
                    wrapped_result = {"results": result_data}

                    self.logger.debug(
                        "Gitleaks scan completed", findings_count=findings_count
                    )
                    return wrapped_result
            except FileNotFoundError:
                # No output file means no secrets found
                self.logger.debug("Gitleaks scan completed", findings_count=0)
                return {"results": []}

        except subprocess.TimeoutExpired:
            self.logger.error("Gitleaks scanner timed out", target_path=target_path)
            raise GitleaksError("Gitleaks scanner timed out")
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON output from Gitleaks", error=str(e))
            raise GitleaksError(f"Invalid JSON output: {e}")
        except subprocess.SubprocessError as e:
            self.logger.error("Failed to run Gitleaks scanner", error=str(e))
            raise GitleaksError(f"Failed to run Gitleaks scanner: {e}")
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except (OSError, FileNotFoundError):
                pass  # File already deleted or doesn't exist


# Convenience function for direct usage
def gitleaks_scan_directory(target_path: str, config: str = None) -> Dict[str, Any]:
    """
    Convenience function to scan a directory with Gitleaks scanner.

    Args:
        target_path: Path to the directory or file to scan
        config: Optional path to custom Gitleaks configuration file

    Returns:
        Dict: JSON-formatted scan results

    Raises:
        GitleaksError: If scanning fails
    """
    logger = get_logger("gitleaks_scanner")
    logger.debug(
        "gitleaks_scan_directory called", target_path=target_path, config=config
    )

    scanner = GitleaksScanner()
    result = scanner.scan(target_path, config)

    logger.debug(
        "gitleaks_scan_directory returning result",
        findings_count=len(result.get("results", [])),
    )
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python gitleaks.py <path_to_scan> [config]")
        sys.exit(1)

    target = sys.argv[1]
    config = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        results = gitleaks_scan_directory(target, config)
        print(json.dumps(results, indent=2))
    except GitleaksError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
