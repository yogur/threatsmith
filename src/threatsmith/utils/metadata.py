import dataclasses
import json
import logging
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from threatsmith import __version__

logger = logging.getLogger(__name__)


@dataclass
class ThreatSmithMetadata:
    threatsmith_version: str
    engine: str
    commit_hash: str
    branch: str
    timestamp: str
    scanners_available: list[str]
    scanners_unavailable: list[str]
    user_objectives: dict

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def generate_metadata(
    engine_name: str,
    scanners_available: list[str],
    scanners_unavailable: list[str],
    user_objectives: dict | None = None,
) -> ThreatSmithMetadata:
    """
    Generate metadata capturing run context for threat model provenance.

    Args:
        engine_name: Name of the AI engine used (e.g., 'claude-code', 'codex')
        scanners_available: List of available scanner names
        scanners_unavailable: List of unavailable scanner names
        user_objectives: Optional dict with 'business' and/or 'security' keys

    Returns:
        ThreatSmithMetadata dataclass with threatsmith_version, engine, commit_hash,
        branch, timestamp (ISO 8601), scanners_available, scanners_unavailable,
        and user_objectives
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

    return ThreatSmithMetadata(
        threatsmith_version=__version__,
        engine=engine_name,
        commit_hash=commit_hash,
        branch=branch,
        timestamp=timestamp,
        scanners_available=scanners_available,
        scanners_unavailable=scanners_unavailable,
        user_objectives=user_objectives or {},
    )


def write_metadata(output_dir: str, metadata: ThreatSmithMetadata) -> None:
    """
    Write metadata to metadata.json in the specified directory.

    Args:
        output_dir: Target directory path
        metadata: ThreatSmithMetadata instance from generate_metadata()
    """
    output_path = Path(output_dir) / "metadata.json"
    logger.debug("Writing metadata to: %s", output_path)
    with open(output_path, "w") as f:
        json.dump(metadata.to_dict(), f, indent=2)
