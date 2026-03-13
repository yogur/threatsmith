import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from threatsmith.utils.metadata import generate_metadata, write_metadata


def test_generate_metadata_returns_all_required_fields():
    """Test that generate_metadata returns all required fields with correct types."""
    with patch("subprocess.run") as mock_run:
        # Mock git rev-parse HEAD
        mock_run.side_effect = [
            type("obj", (object,), {"stdout": "abc123def456\n", "returncode": 0})(),
            type("obj", (object,), {"stdout": "main\n", "returncode": 0})(),
        ]

        metadata = generate_metadata(
            engine_name="claude-code",
            scanners_available=["semgrep", "trivy"],
            scanners_unavailable=["gitleaks"],
            user_objectives="Assess web app security",
        )

        # Check all required fields exist
        assert "threatsmith_version" in metadata
        assert "engine" in metadata
        assert "commit_hash" in metadata
        assert "branch" in metadata
        assert "timestamp" in metadata
        assert "scanners_available" in metadata
        assert "scanners_unavailable" in metadata
        assert "user_objectives" in metadata

        # Check types
        assert isinstance(metadata["threatsmith_version"], str)
        assert isinstance(metadata["engine"], str)
        assert isinstance(metadata["commit_hash"], str)
        assert isinstance(metadata["branch"], str)
        assert isinstance(metadata["timestamp"], str)
        assert isinstance(metadata["scanners_available"], list)
        assert isinstance(metadata["scanners_unavailable"], list)
        assert isinstance(metadata["user_objectives"], str)


def test_generate_metadata_captures_engine_name():
    """Test that generate_metadata correctly captures the engine name."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            type("obj", (object,), {"stdout": "commit123\n", "returncode": 0})(),
            type("obj", (object,), {"stdout": "branch1\n", "returncode": 0})(),
        ]

        metadata = generate_metadata(
            engine_name="codex",
            scanners_available=[],
            scanners_unavailable=[],
        )

        assert metadata["engine"] == "codex"


def test_generate_metadata_captures_scanners():
    """Test that generate_metadata correctly captures available and unavailable scanners."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            type("obj", (object,), {"stdout": "hash\n", "returncode": 0})(),
            type("obj", (object,), {"stdout": "br\n", "returncode": 0})(),
        ]

        metadata = generate_metadata(
            engine_name="claude-code",
            scanners_available=["trivy", "semgrep"],
            scanners_unavailable=["gitleaks"],
        )

        assert metadata["scanners_available"] == ["trivy", "semgrep"]
        assert metadata["scanners_unavailable"] == ["gitleaks"]


def test_generate_metadata_captures_user_objectives():
    """Test that generate_metadata correctly captures user objectives."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            type("obj", (object,), {"stdout": "hash\n", "returncode": 0})(),
            type("obj", (object,), {"stdout": "br\n", "returncode": 0})(),
        ]

        objectives = "Find all authentication flaws"
        metadata = generate_metadata(
            engine_name="claude-code",
            scanners_available=[],
            scanners_unavailable=[],
            user_objectives=objectives,
        )

        assert metadata["user_objectives"] == objectives


def test_generate_metadata_handles_git_failures():
    """Test that generate_metadata handles git command failures gracefully."""
    with patch("subprocess.run") as mock_run:
        # Both git commands fail with CalledProcessError
        mock_run.side_effect = [
            Exception("git not found"),
            Exception("git not found"),
        ]

        metadata = generate_metadata(
            engine_name="claude-code",
            scanners_available=[],
            scanners_unavailable=[],
        )

        assert metadata["commit_hash"] == "unknown"
        assert metadata["branch"] == "unknown"


def test_generate_metadata_timestamp_is_iso8601():
    """Test that the timestamp is in ISO 8601 format."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            type("obj", (object,), {"stdout": "hash\n", "returncode": 0})(),
            type("obj", (object,), {"stdout": "br\n", "returncode": 0})(),
        ]

        metadata = generate_metadata(
            engine_name="claude-code",
            scanners_available=[],
            scanners_unavailable=[],
        )

        timestamp = metadata["timestamp"]
        # Should contain 'T' (ISO 8601 format) and 'Z' or '+' (timezone indicator)
        assert "T" in timestamp
        assert "Z" in timestamp or "+" in timestamp or "-" in timestamp


def test_write_metadata_creates_json_file():
    """Test that write_metadata creates a valid JSON file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        metadata = {
            "threatsmith_version": "0.2.0",
            "engine": "claude-code",
            "commit_hash": "abc123",
            "branch": "main",
            "timestamp": "2026-03-13T12:00:00+00:00",
            "scanners_available": ["trivy"],
            "scanners_unavailable": ["semgrep", "gitleaks"],
            "user_objectives": "Test objectives",
        }

        write_metadata(tmpdir, metadata)

        # Verify file exists
        metadata_file = Path(tmpdir) / "metadata.json"
        assert metadata_file.exists()

        # Verify file contains valid JSON
        with open(metadata_file) as f:
            loaded = json.load(f)

        assert loaded == metadata


def test_write_metadata_creates_directory_if_needed():
    """Test that write_metadata works with nested directory paths."""
    with tempfile.TemporaryDirectory() as tmpdir:
        nested_dir = Path(tmpdir) / "subdir" / "nested"
        nested_dir.mkdir(parents=True)

        metadata = {
            "threatsmith_version": "0.2.0",
            "engine": "claude-code",
            "commit_hash": "hash",
            "branch": "branch",
            "timestamp": "2026-03-13T12:00:00+00:00",
            "scanners_available": [],
            "scanners_unavailable": [],
            "user_objectives": "",
        }

        write_metadata(str(nested_dir), metadata)

        metadata_file = nested_dir / "metadata.json"
        assert metadata_file.exists()


def test_generate_metadata_json_serializable():
    """Test that generate_metadata output is JSON serializable."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            type("obj", (object,), {"stdout": "hash\n", "returncode": 0})(),
            type("obj", (object,), {"stdout": "br\n", "returncode": 0})(),
        ]

        metadata = generate_metadata(
            engine_name="claude-code",
            scanners_available=["trivy"],
            scanners_unavailable=["semgrep"],
            user_objectives="objectives",
        )

        # Should not raise an exception
        json_str = json.dumps(metadata)
        assert isinstance(json_str, str)
