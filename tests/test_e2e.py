"""End-to-end integration tests for the full ThreatSmith pipeline (US-018)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from threatsmith.engines.base import Engine
from threatsmith.main import app

runner = CliRunner()

_STAGE_FILENAMES = [
    "01-objectives.md",
    "02-technical-scope.md",
    "03-application-decomposition.md",
    "04-threat-analysis.md",
    "05-vulnerability-analysis.md",
    "06-attack-modeling.md",
    "07-risk-and-impact-analysis.md",
    "08-report.md",
]

_REQUIRED_METADATA_FIELDS = [
    "threatsmith_version",
    "engine",
    "framework",
    "commit_hash",
    "branch",
    "timestamp",
    "scanners_available",
    "scanners_unavailable",
    "user_objectives",
]


def _make_writing_engine(output_dir: str) -> Engine:
    """Return a mock Engine that writes realistic deliverable files for each stage."""
    engine = MagicMock(spec=Engine)
    call_count = {"n": 0}

    def execute_side_effect(
        prompt: str, working_directory: str, output_dir: str
    ) -> int:
        call_count["n"] += 1
        stage_idx = call_count["n"] - 1
        filename = _STAGE_FILENAMES[stage_idx]
        out_path = os.path.join(working_directory, output_dir, filename)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        stage_num = stage_idx + 1
        with open(out_path, "w") as fh:
            fh.write(
                f"# Stage {stage_num} Deliverable\n\n"
                f"## Overview\n\nThis is stage {stage_num} output with realistic content.\n\n"
                f"## Findings\n\nDetailed analysis for stage {stage_num}.\n"
            )
        return 0

    engine.execute.side_effect = execute_side_effect
    return engine


# ---------------------------------------------------------------------------
# Full pipeline — deliverable files created
# ---------------------------------------------------------------------------


def test_e2e_full_pipeline_creates_all_deliverables(tmp_path):
    """All 8 deliverable files are created after a successful pipeline run."""
    output_dir = "threatmodel"
    mock_engine = _make_writing_engine(output_dir)

    with patch("threatsmith.main.get_engine", return_value=mock_engine):
        result = runner.invoke(app, [str(tmp_path), "--framework", "pasta"])

    assert result.exit_code == 0
    for filename in _STAGE_FILENAMES:
        assert os.path.isfile(tmp_path / output_dir / filename), (
            f"Expected deliverable file not found: {filename}"
        )


# ---------------------------------------------------------------------------
# Metadata — required fields present in metadata.json
# ---------------------------------------------------------------------------


def test_e2e_metadata_json_created_with_required_fields(tmp_path):
    """metadata.json is created and contains all required fields."""
    output_dir = "threatmodel"
    mock_engine = _make_writing_engine(output_dir)

    with patch("threatsmith.main.get_engine", return_value=mock_engine):
        runner.invoke(app, [str(tmp_path), "--framework", "pasta"])

    metadata_path = tmp_path / output_dir / "metadata.json"
    assert metadata_path.is_file(), "metadata.json was not created"

    with open(metadata_path) as fh:
        metadata = json.load(fh)

    for field_name in _REQUIRED_METADATA_FIELDS:
        assert field_name in metadata, f"Required metadata field missing: {field_name}"


# ---------------------------------------------------------------------------
# Context accumulation — stage N prompt contains prior stage outputs
# ---------------------------------------------------------------------------


def test_e2e_context_accumulates_correctly(tmp_path):
    """Stage N prompt contains the outputs from stages 1 through N-1."""
    captured_prompts: list[str] = []
    call_count = {"n": 0}

    engine = MagicMock(spec=Engine)

    def execute_side_effect(
        prompt: str, working_directory: str, output_dir: str
    ) -> int:
        captured_prompts.append(prompt)
        call_count["n"] += 1
        stage_idx = call_count["n"] - 1
        filename = _STAGE_FILENAMES[stage_idx]
        out_path = os.path.join(working_directory, output_dir, filename)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        stage_num = stage_idx + 1
        with open(out_path, "w") as fh:
            fh.write(f"# Stage {stage_num} unique marker content\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    with patch("threatsmith.main.get_engine", return_value=engine):
        result = runner.invoke(app, [str(tmp_path), "--framework", "pasta"])

    assert result.exit_code == 0
    assert len(captured_prompts) == 8

    # Stage 1 has no prior outputs (nothing to assert)
    # Stage 2 prompt must contain stage 1 output
    assert "Stage 1 unique marker content" in captured_prompts[1]

    # Stage 3 prompt must contain stages 1 and 2 outputs
    assert "Stage 1 unique marker content" in captured_prompts[2]
    assert "Stage 2 unique marker content" in captured_prompts[2]

    # Stage 8 (report consolidation) prompt must contain outputs from stages 1–7
    for stage_num in range(1, 8):
        assert f"Stage {stage_num} unique marker content" in captured_prompts[7], (
            f"Stage 8 prompt missing output from stage {stage_num}"
        )
