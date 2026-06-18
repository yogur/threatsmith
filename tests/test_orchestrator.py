"""Tests for the Orchestrator class."""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock

from threatsmith.engines.base import Engine
from threatsmith.frameworks.pasta import build_pasta_pack
from threatsmith.frameworks.types import FrameworkPack, StageSpec
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


def _pasta():
    return build_pasta_pack()


# ---------------------------------------------------------------------------
# Full pipeline success
# ---------------------------------------------------------------------------


def test_run_full_pipeline_success(tmp_path):
    """Orchestrator returns 0 when all stages succeed and produce output files."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    result = orch.run()

    assert result == 0
    assert engine.execute.call_count == 8


def test_run_invokes_engine_with_repo_path(tmp_path):
    """Engine.execute() is called with the repo_path as working_directory."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    orch.run()

    for c in engine.execute.call_args_list:
        assert c[0][1] == str(tmp_path)


# ---------------------------------------------------------------------------
# Instruction content — Model B file-pointer approach
# ---------------------------------------------------------------------------


def test_instruction_contains_skill_name(tmp_path):
    """Each per-stage instruction names the pack's installed skill."""
    captured_instructions: list[str] = []
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        captured_instructions.append(instruction)
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    orch.run()

    for instruction in captured_instructions:
        assert "threatsmith-pasta" in instruction


def test_instruction_contains_mode(tmp_path):
    """Per-stage instructions include the configured mode."""
    captured_instructions: list[str] = []
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        captured_instructions.append(instruction)
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
        mode="from-docs",
    )
    orch.run()

    for instruction in captured_instructions:
        assert "from-docs" in instruction


def test_instruction_contains_output_dir(tmp_path):
    """Per-stage instructions reference the output directory."""
    captured_instructions: list[str] = []
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        captured_instructions.append(instruction)
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    orch.run()

    for instruction in captured_instructions:
        assert "threatmodel" in instruction


def test_no_prior_stage_text_inlined(tmp_path):
    """Prompts do not inline prior-stage content — context is file-pointer only."""
    captured_instructions: list[str] = []
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        captured_instructions.append(instruction)
        call_count = engine.execute.call_count
        out_dir = os.path.join(working_directory, output_dir)
        os.makedirs(out_dir, exist_ok=True)
        filename = _STAGE_FILENAMES[call_count - 1]
        with open(os.path.join(out_dir, filename), "w") as fh:
            fh.write(f"UNIQUE_SENTINEL_STAGE_{call_count}\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    orch.run()

    # Later instructions must NOT contain the unique content from earlier stages
    for idx, instruction in enumerate(captured_instructions[1:], start=1):
        assert f"UNIQUE_SENTINEL_STAGE_{idx}" not in instruction
        assert "<prior_stages>" not in instruction


# ---------------------------------------------------------------------------
# Failure: non-zero exit code
# ---------------------------------------------------------------------------


def test_non_zero_exit_code_aborts_pipeline(tmp_path):
    """Engine returning a non-zero exit code causes the pipeline to abort."""
    engine = _make_engine(exit_code=1)

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )

    assert orch.run() == 1


def test_missing_output_file_aborts_pipeline(tmp_path):
    """Engine returning success without writing output aborts the pipeline."""
    engine = _make_engine(exit_code=0)  # claims success but writes no files

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )

    assert orch.run() == 1


def test_pipeline_aborts_at_failing_stage(tmp_path):
    """Pipeline stops at the first failing stage and does not continue."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        call_count = engine.execute.call_count
        if call_count <= 2:
            _write_stage_files(
                os.path.join(working_directory, output_dir), stages=[call_count]
            )
            return 0
        return 1

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    result = orch.run()

    assert result == 1
    assert engine.execute.call_count == 3


# ---------------------------------------------------------------------------
# stages_completed counter
# ---------------------------------------------------------------------------


def test_stages_completed_increments_per_successful_stage(tmp_path):
    """stages_completed reflects how many stages produced their output file."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    orch.run()

    assert orch.stages_completed == 8


def test_stages_completed_reflects_partial_run(tmp_path):
    """stages_completed equals the number of stages before the failure."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        call_count = engine.execute.call_count
        if call_count <= 3:
            _write_stage_files(
                os.path.join(working_directory, output_dir), stages=[call_count]
            )
            return 0
        return 1

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="threatmodel",
    )
    orch.run()

    assert orch.stages_completed == 3


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def test_stage_messages_appear_in_log(tmp_path, caplog):
    """Stage start and completion messages are emitted at INFO level."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    with caplog.at_level(logging.INFO, logger="threatsmith.orchestrator"):
        orch = Orchestrator(
            engine=engine,
            repo_path=str(tmp_path),
            pack=_pasta(),
            output_dir="threatmodel",
        )
        orch.run()

    assert "Stage 1" in caplog.text
    assert "complete" in caplog.text.lower()


# ---------------------------------------------------------------------------
# Custom output_dir
# ---------------------------------------------------------------------------


def test_custom_output_dir(tmp_path):
    """Orchestrator respects a custom output_dir parameter."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(instruction, working_directory, output_dir):
        call_count = engine.execute.call_count
        _write_stage_files(
            os.path.join(working_directory, output_dir), stages=[call_count]
        )
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=_pasta(),
        output_dir="custom_output",
    )
    result = orch.run()

    assert result == 0


# ---------------------------------------------------------------------------
# Mock 3-stage pack — framework-agnostic behaviour
# ---------------------------------------------------------------------------


def _make_mock_pack() -> FrameworkPack:
    """Return a minimal 3-stage FrameworkPack (2 analysis + 1 report)."""
    stages = [
        StageSpec(number=1, name="mock_stage_one", output_file="01-mock-one.md"),
        StageSpec(number=2, name="mock_stage_two", output_file="02-mock-two.md"),
    ]
    report = StageSpec(number=3, name="mock_report", output_file="03-mock-report.md")
    return FrameworkPack(
        name="mock",
        display_name="Mock Framework",
        description="Mock framework for testing",
        stages=stages,
        report_stage=report,
        skill_name="mock-skill",
    )


def test_mock_3stage_pack_full_pipeline_success(tmp_path):
    """Orchestrator runs all 3 stages of a mock pack and returns 0."""
    mock_pack = _make_mock_pack()
    all_files = ["01-mock-one.md", "02-mock-two.md", "03-mock-report.md"]
    engine = MagicMock(spec=Engine)
    call_state = {"n": 0}

    def execute_side_effect(instruction, working_directory, output_dir):
        call_state["n"] += 1
        out_dir = os.path.join(working_directory, output_dir)
        os.makedirs(out_dir, exist_ok=True)
        filename = all_files[call_state["n"] - 1]
        with open(os.path.join(out_dir, filename), "w") as fh:
            fh.write(f"# {filename} output\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=mock_pack,
        output_dir="threatmodel",
    )
    result = orch.run()

    assert result == 0
    assert engine.execute.call_count == 3


def test_mock_pack_output_validation_uses_framework_filenames(tmp_path):
    """Output validation checks stage.output_file, not hardcoded names."""
    mock_pack = _make_mock_pack()
    engine = MagicMock(spec=Engine)

    # Engine "succeeds" but writes a file with the wrong name
    def execute_side_effect(instruction, working_directory, output_dir):
        out_dir = os.path.join(working_directory, output_dir)
        os.makedirs(out_dir, exist_ok=True)
        # Write a file with wrong name — orchestrator should not accept it
        with open(os.path.join(out_dir, "wrong-name.md"), "w") as fh:
            fh.write("wrong file\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=mock_pack,
        output_dir="threatmodel",
    )
    result = orch.run()

    # Should fail because 01-mock-one.md was not written
    assert result == 1


def test_mock_pack_skill_name_in_instruction(tmp_path):
    """Mock pack's skill name appears in each per-stage instruction."""
    mock_pack = _make_mock_pack()
    all_files = ["01-mock-one.md", "02-mock-two.md", "03-mock-report.md"]
    captured_instructions: list[str] = []
    engine = MagicMock(spec=Engine)
    call_state = {"n": 0}

    def execute_side_effect(instruction, working_directory, output_dir):
        captured_instructions.append(instruction)
        call_state["n"] += 1
        out_dir = os.path.join(working_directory, output_dir)
        os.makedirs(out_dir, exist_ok=True)
        filename = all_files[call_state["n"] - 1]
        with open(os.path.join(out_dir, filename), "w") as fh:
            fh.write(f"content for {filename}\n")
        return 0

    engine.execute.side_effect = execute_side_effect

    orch = Orchestrator(
        engine=engine,
        repo_path=str(tmp_path),
        pack=mock_pack,
        output_dir="threatmodel",
    )
    orch.run()

    for instruction in captured_instructions:
        assert "mock-skill" in instruction
