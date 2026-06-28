"""End-to-end integration tests for the full 4QF+STRIDE pipeline."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from threatsmith.engines.base import Engine
from threatsmith.main import app

runner = CliRunner()

_STAGE_FILENAMES = [
    "01-system-model.md",
    "02-threat-identification.md",
    "03-mitigations.md",
    "04-validation.md",
    "05-report.md",
]


def _make_writing_engine(output_dir: str) -> Engine:
    """Return a mock Engine that writes realistic deliverable files for each stage."""
    engine = MagicMock(spec=Engine)
    call_count = {"n": 0}

    def execute_side_effect(
        instruction: str, working_directory: str, output_dir: str
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
# Full pipeline — all 5 deliverable files created
# ---------------------------------------------------------------------------


def test_e2e_stride4q_full_pipeline_creates_all_deliverables(tmp_path):
    """All 5 deliverable files are created after a successful 4QF+STRIDE pipeline run."""
    output_dir = "threatmodel"
    mock_engine = _make_writing_engine(output_dir)

    with patch("threatsmith.main.get_engine", return_value=mock_engine):
        result = runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
                "--framework",
                "stride-4q",
            ],
        )

    assert result.exit_code == 0
    for filename in _STAGE_FILENAMES:
        assert os.path.isfile(tmp_path / output_dir / filename), (
            f"Expected deliverable file not found: {filename}"
        )


# ---------------------------------------------------------------------------
# Per-stage instructions target the installed skill
# ---------------------------------------------------------------------------


def test_e2e_stride4q_instructions_name_skill(tmp_path):
    """Each per-stage instruction names the threatsmith-stride-4q skill."""
    captured_instructions: list[str] = []
    call_count = {"n": 0}
    engine = MagicMock(spec=Engine)

    def execute_side_effect(
        instruction: str, working_directory: str, output_dir: str
    ) -> int:
        captured_instructions.append(instruction)
        call_count["n"] += 1
        stage_idx = call_count["n"] - 1
        filename = _STAGE_FILENAMES[stage_idx]
        out_path = os.path.join(working_directory, output_dir, filename)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fh:
            fh.write(f"# Stage {call_count['n']} content\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    with patch("threatsmith.main.get_engine", return_value=engine):
        result = runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
                "--framework",
                "stride-4q",
            ],
        )

    assert result.exit_code == 0
    assert len(captured_instructions) == 5
    for instruction in captured_instructions:
        assert "threatsmith-stride-4q" in instruction


def test_e2e_stride4q_instructions_do_not_inline_prior_stage_content(tmp_path):
    """Per-stage instructions do not inline prior stage output content."""
    captured_instructions: list[str] = []
    call_count = {"n": 0}
    engine = MagicMock(spec=Engine)

    def execute_side_effect(
        instruction: str, working_directory: str, output_dir: str
    ) -> int:
        captured_instructions.append(instruction)
        call_count["n"] += 1
        stage_idx = call_count["n"] - 1
        filename = _STAGE_FILENAMES[stage_idx]
        out_path = os.path.join(working_directory, output_dir, filename)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as fh:
            fh.write(f"UNIQUE_SENTINEL_STRIDE_{call_count['n']}\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    with patch("threatsmith.main.get_engine", return_value=engine):
        result = runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
                "--framework",
                "stride-4q",
            ],
        )

    assert result.exit_code == 0
    for idx, instruction in enumerate(captured_instructions[1:], start=1):
        assert f"UNIQUE_SENTINEL_STRIDE_{idx}" not in instruction
        assert "<prior_stages>" not in instruction


# ---------------------------------------------------------------------------
# Metadata — framework field is "stride-4q"
# ---------------------------------------------------------------------------


def test_e2e_stride4q_metadata_contains_framework(tmp_path):
    """metadata.json includes framework: 'stride-4q'."""
    output_dir = "threatmodel"
    mock_engine = _make_writing_engine(output_dir)

    with patch("threatsmith.main.get_engine", return_value=mock_engine):
        runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
                "--framework",
                "stride-4q",
            ],
        )

    metadata_path = tmp_path / output_dir / "metadata.json"
    assert metadata_path.is_file(), "metadata.json was not created"

    with open(metadata_path) as fh:
        metadata = json.load(fh)

    assert metadata.get("framework") == "stride-4q", (
        f"Expected framework='stride-4q', got {metadata.get('framework')!r}"
    )


def test_e2e_stride4q_metadata_has_no_scanner_fields(tmp_path):
    """metadata.json does not include scanner availability fields."""
    output_dir = "threatmodel"
    mock_engine = _make_writing_engine(output_dir)

    with patch("threatsmith.main.get_engine", return_value=mock_engine):
        runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
                "--framework",
                "stride-4q",
            ],
        )

    metadata_path = tmp_path / output_dir / "metadata.json"
    assert metadata_path.is_file()

    with open(metadata_path) as fh:
        metadata = json.load(fh)

    assert "scanners_available" not in metadata
    assert "scanners_unavailable" not in metadata
