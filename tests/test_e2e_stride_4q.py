"""End-to-end integration tests for the full 4QF+STRIDE pipeline (US-F34)."""

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
# Full pipeline — all 5 deliverable files created
# ---------------------------------------------------------------------------


def test_e2e_stride4q_full_pipeline_creates_all_deliverables(tmp_path):
    """All 5 deliverable files are created after a successful 4QF+STRIDE pipeline run."""
    output_dir = "threatmodel"
    mock_engine = _make_writing_engine(output_dir)

    with patch("threatsmith.main.get_engine", return_value=mock_engine):
        result = runner.invoke(app, [str(tmp_path), "--framework", "stride-4q"])

    assert result.exit_code == 0
    for filename in _STAGE_FILENAMES:
        assert os.path.isfile(tmp_path / output_dir / filename), (
            f"Expected deliverable file not found: {filename}"
        )


# ---------------------------------------------------------------------------
# Stage 2 prompt contains STRIDE categories reference
# ---------------------------------------------------------------------------


def test_e2e_stride4q_stage2_prompt_contains_stride_categories(tmp_path):
    """Stage 2 prompt includes the STRIDE categories reference text."""
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
        with open(out_path, "w") as fh:
            fh.write(f"# Stage {call_count['n']} content\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    with patch("threatsmith.main.get_engine", return_value=engine):
        result = runner.invoke(app, [str(tmp_path), "--framework", "stride-4q"])

    assert result.exit_code == 0
    assert len(captured_prompts) == 5
    # Stage 2 is index 1
    assert "STRIDE" in captured_prompts[1], (
        "Stage 2 prompt should contain STRIDE categories reference"
    )
    assert "Spoofing" in captured_prompts[1], (
        "Stage 2 prompt should contain Spoofing from STRIDE categories"
    )


# ---------------------------------------------------------------------------
# Metadata — framework field is "stride-4q"
# ---------------------------------------------------------------------------


def test_e2e_stride4q_metadata_contains_framework(tmp_path):
    """metadata.json includes framework: 'stride-4q'."""
    output_dir = "threatmodel"
    mock_engine = _make_writing_engine(output_dir)

    with patch("threatsmith.main.get_engine", return_value=mock_engine):
        runner.invoke(app, [str(tmp_path), "--framework", "stride-4q"])

    metadata_path = tmp_path / output_dir / "metadata.json"
    assert metadata_path.is_file(), "metadata.json was not created"

    with open(metadata_path) as fh:
        metadata = json.load(fh)

    assert metadata.get("framework") == "stride-4q", (
        f"Expected framework='stride-4q', got {metadata.get('framework')!r}"
    )


# ---------------------------------------------------------------------------
# Context accumulation — each stage's prompt includes prior stage outputs
# ---------------------------------------------------------------------------


def test_e2e_stride4q_context_accumulates_across_stages(tmp_path):
    """Each stage N prompt contains prior stage outputs from stages 1 through N-1."""
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
        result = runner.invoke(app, [str(tmp_path), "--framework", "stride-4q"])

    assert result.exit_code == 0
    assert len(captured_prompts) == 5

    # Stage 2 prompt must contain stage 1 output
    assert "Stage 1 unique marker content" in captured_prompts[1]

    # Stage 3 prompt must contain stages 1 and 2 outputs
    assert "Stage 1 unique marker content" in captured_prompts[2]
    assert "Stage 2 unique marker content" in captured_prompts[2]

    # Stage 4 prompt must contain stages 1, 2, and 3 outputs
    assert "Stage 1 unique marker content" in captured_prompts[3]
    assert "Stage 2 unique marker content" in captured_prompts[3]
    assert "Stage 3 unique marker content" in captured_prompts[3]

    # Stage 5 (report consolidation) prompt must contain outputs from all 4 analysis stages
    for stage_num in range(1, 5):
        assert f"Stage {stage_num} unique marker content" in captured_prompts[4], (
            f"Stage 5 prompt missing output from stage {stage_num}"
        )
