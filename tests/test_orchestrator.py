"""Tests for the Orchestrator class (US-016)."""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock

from threatsmith.engines.base import Engine
from threatsmith.orchestrator import Orchestrator

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _make_engine(exit_code: int = 0) -> Engine:
    """Return a mock engine that always succeeds."""
    engine = MagicMock(spec=Engine)
    engine.execute.return_value = exit_code
    return engine


def _write_stage_files(output_dir: str, stages: list[int] | None = None) -> None:
    """Write dummy deliverable files for the given stage numbers (1-8)."""
    if stages is None:
        stages = list(range(1, 9))
    os.makedirs(output_dir, exist_ok=True)
    for i in stages:
        filename = _STAGE_FILENAMES[i - 1]
        with open(os.path.join(output_dir, filename), "w") as fh:
            fh.write(f"# Stage {i} output\nContent for stage {i}.\n")


# ---------------------------------------------------------------------------
# Full pipeline success
# ---------------------------------------------------------------------------


def test_run_full_pipeline_success(tmp_path):
    """Orchestrator returns 0 when all stages succeed and produce output files."""
    output_dir = str(tmp_path / "threatmodel")

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        # Write the next expected file on each call
        call_count = engine.execute.call_count
        _write_stage_files(output_dir, stages=[call_count])
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
    )
    result = orch.run()

    assert result == 0
    assert engine.execute.call_count == 8


def test_run_invokes_engine_with_repo_path(tmp_path):
    """Engine.execute() is called with the repo_path as working_directory."""
    output_dir = str(tmp_path / "threatmodel")

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        call_count = engine.execute.call_count
        _write_stage_files(output_dir, stages=[call_count])
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
    )
    orch.run()

    for c in engine.execute.call_args_list:
        assert c[0][1] == str(tmp_path)


# ---------------------------------------------------------------------------
# Context accumulation
# ---------------------------------------------------------------------------


def test_context_accumulates_across_stages(tmp_path):
    """Each stage's prompt contains outputs from all prior stages."""
    output_dir = str(tmp_path / "threatmodel")
    captured_prompts: list[str] = []

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        captured_prompts.append(prompt)
        call_count = engine.execute.call_count
        _write_stage_files(output_dir, stages=[call_count])
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
    )
    orch.run()

    # Stage 1 prompt has no prior outputs — no XML prior_stages block needed
    assert len(captured_prompts) == 8

    # Stage 2 prompt should reference stage 1 output content
    assert "Stage 1 output" in captured_prompts[1]

    # Stage 3 prompt should reference stage 1 and stage 2 outputs
    assert "Stage 1 output" in captured_prompts[2]
    assert "Stage 2 output" in captured_prompts[2]

    # Stage 8 prompt should reference outputs from stages 1–7
    for i in range(1, 8):
        assert f"Stage {i} output" in captured_prompts[7]


# ---------------------------------------------------------------------------
# Failure: non-zero exit code
# ---------------------------------------------------------------------------


def test_stage_failure_non_zero_exit_code_retries_then_aborts(tmp_path):
    """Non-zero exit code causes one retry, then abort with exit code 1."""
    engine = _make_engine(exit_code=1)

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
    )
    result = orch.run()

    assert result == 1
    # Stage 1 tried twice (original + 1 retry), then aborted
    assert engine.execute.call_count == 2


def test_stage_failure_missing_output_file_retries_then_aborts(tmp_path):
    """Missing output file causes one retry, then abort with exit code 1."""
    engine = _make_engine(exit_code=0)
    # Engine succeeds but never writes files

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
    )
    result = orch.run()

    assert result == 1
    # Stage 1 tried twice (original + 1 retry), then aborted
    assert engine.execute.call_count == 2


def test_stage_retry_succeeds_on_second_attempt(tmp_path):
    """If stage fails on first attempt but succeeds on retry, pipeline continues."""
    output_dir = str(tmp_path / "threatmodel")
    call_count_tracker = {"n": 0}

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        call_count_tracker["n"] += 1
        n = call_count_tracker["n"]
        if n == 1:
            # First call for stage 1: fail with non-zero exit code
            return 1
        # Stage 1 retry and all subsequent stages succeed
        # n=2 → stage 1 file, n=3 → stage 2 file, ..., n=9 → stage 8 file.
        file_index = n - 1  # n=2 → stage 1, n=3 → stage 2, ..., n=9 → stage 8
        _write_stage_files(output_dir, stages=[file_index])
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
    )
    result = orch.run()

    assert result == 0
    # 1 failure + 1 retry for stage 1 + 7 successful stages = 9 calls
    assert engine.execute.call_count == 9


def test_pipeline_aborts_at_failing_stage(tmp_path):
    """Pipeline stops at the first failing stage and does not continue."""
    output_dir = str(tmp_path / "threatmodel")

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        call_count = engine.execute.call_count
        # Fail stage 3 (calls 5 and 6 are the two attempts for stage 3;
        # calls 1,2 are stage 1; 3,4 are stage 2... wait, no.
        # With success for stages 1 and 2 each requiring 1 call,
        # calls 1→stage1, 2→stage2, 3→stage3 attempt1, 4→stage3 attempt2 (abort)
        if call_count <= 2:
            # Stages 1 and 2 succeed
            _write_stage_files(output_dir, stages=[call_count])
            return 0
        # Stage 3 always fails
        return 1

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
    )
    result = orch.run()

    assert result == 1
    # Stages 1, 2 succeed (1 call each) + stage 3 retried twice = 4 calls total
    assert engine.execute.call_count == 4


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def test_stage_messages_appear_in_log(tmp_path, caplog):
    """Stage start and completion messages are emitted at INFO level."""
    output_dir = str(tmp_path / "threatmodel")

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        call_count = engine.execute.call_count
        _write_stage_files(output_dir, stages=[call_count])
        return 0

    engine.execute.side_effect = execute_side_effect

    with caplog.at_level(logging.INFO, logger="threatsmith.orchestrator"):
        orch = Orchestrator(
            engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
        )
        orch.run()

    assert "Stage 1" in caplog.text
    assert "complete" in caplog.text.lower()


def test_context_size_only_in_debug_log(tmp_path, caplog):
    """Accumulated context size is a DEBUG-only detail, not visible at INFO level."""
    output_dir = str(tmp_path / "threatmodel")

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        call_count = engine.execute.call_count
        _write_stage_files(output_dir, stages=[call_count])
        return 0

    engine.execute.side_effect = execute_side_effect

    with caplog.at_level(logging.INFO, logger="threatsmith.orchestrator"):
        orch = Orchestrator(
            engine=engine, repo_path=str(tmp_path), output_dir="threatmodel"
        )
        orch.run()

    assert "chars" not in caplog.text


# ---------------------------------------------------------------------------
# Custom output_dir
# ---------------------------------------------------------------------------


def test_custom_output_dir(tmp_path):
    """Orchestrator respects a custom output_dir parameter."""
    output_dir = str(tmp_path / "custom_output")

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory):
        call_count = engine.execute.call_count
        _write_stage_files(output_dir, stages=[call_count])
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine, repo_path=str(tmp_path), output_dir="custom_output"
    )
    result = orch.run()

    assert result == 0
