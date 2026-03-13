import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from threatsmith import __version__


def generate_metadata(
    engine_name: str,
    scanners_available: list[str],
    scanners_unavailable: list[str],
    user_objectives: str = "",
) -> dict:
    """
    Generate metadata dict capturing run context for threat model provenance.

    Args:
        engine_name: Name of the AI engine used (e.g., 'claude-code', 'codex')
        scanners_available: List of available scanner names
        scanners_unavailable: List of unavailable scanner names
        user_objectives: Optional user-supplied objectives string

    Returns:
        dict: JSON-serializable metadata dict with threatsmith_version, engine_name,
              commit_hash, branch, timestamp (ISO 8601), scanners_available,
              scanners_unavailable, and user_objectives
    """
    # Get commit hash
    try:
        commit_hash = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except Exception:
        commit_hash = "unknown"

    # Get branch name
    try:
        branch = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except Exception:
        branch = "unknown"

    # ISO 8601 timestamp with timezone
    timestamp = datetime.now(UTC).isoformat()

    return {
        "threatsmith_version": __version__,
        "engine": engine_name,
        "commit_hash": commit_hash,
        "branch": branch,
        "timestamp": timestamp,
        "scanners_available": scanners_available,
        "scanners_unavailable": scanners_unavailable,
        "user_objectives": user_objectives,
    }


def write_metadata(output_dir: str, metadata: dict) -> None:
    """
    Write metadata dict to metadata.json in the specified directory.

    Args:
        output_dir: Target directory path
        metadata: Metadata dict from generate_metadata()
    """
    output_path = Path(output_dir) / "metadata.json"
    with open(output_path, "w") as f:
        json.dump(metadata, f, indent=2)
