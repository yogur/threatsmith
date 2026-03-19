"""Tests for the Orchestrator class."""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock

from threatsmith.engines.base import Engine
from threatsmith.frameworks.pasta import build_pasta_pack
from threatsmith.frameworks.types import FrameworkPack, StageContext, StageSpec
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

    def execute_side_effect(prompt, working_directory, output_dir):
        # Write the next expected file on each call
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

    def execute_side_effect(prompt, working_directory, output_dir):
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
# Context accumulation
# ---------------------------------------------------------------------------


def test_context_accumulates_across_stages(tmp_path):
    """Each stage's prompt contains outputs from all prior stages."""
    captured_prompts: list[str] = []

    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory, output_dir):
        captured_prompts.append(prompt)
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

    def execute_side_effect(prompt, working_directory, output_dir):
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
# Logging
# ---------------------------------------------------------------------------


def test_stage_messages_appear_in_log(tmp_path, caplog):
    """Stage start and completion messages are emitted at INFO level."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory, output_dir):
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


def test_context_size_only_in_debug_log(tmp_path, caplog):
    """Accumulated context size is a DEBUG-only detail, not visible at INFO level."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory, output_dir):
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

    assert "chars" not in caplog.text


# ---------------------------------------------------------------------------
# Custom output_dir
# ---------------------------------------------------------------------------


def test_custom_output_dir(tmp_path):
    """Orchestrator respects a custom output_dir parameter."""
    engine = MagicMock(spec=Engine)

    def execute_side_effect(prompt, working_directory, output_dir):
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


def _build_mock_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
    """Minimal build_prompt for mock stages."""
    prior = " ".join(context.prior_outputs.values())
    return f"mock prompt prior={prior}"


def _make_mock_pack() -> FrameworkPack:
    """Return a minimal 3-stage FrameworkPack (2 analysis + 1 report)."""
    stages = [
        StageSpec(
            number=1,
            name="mock_stage_one",
            output_file="01-mock-one.md",
            build_prompt=_build_mock_prompt,
        ),
        StageSpec(
            number=2,
            name="mock_stage_two",
            output_file="02-mock-two.md",
            build_prompt=_build_mock_prompt,
        ),
    ]
    report = StageSpec(
        number=3,
        name="mock_report",
        output_file="03-mock-report.md",
        build_prompt=_build_mock_prompt,
    )
    return FrameworkPack(
        name="mock",
        display_name="Mock Framework",
        description="Mock framework for testing",
        stages=stages,
        report_stage=report,
    )


def test_mock_3stage_pack_full_pipeline_success(tmp_path):
    """Orchestrator runs all 3 stages of a mock pack and returns 0."""
    mock_pack = _make_mock_pack()
    all_files = ["01-mock-one.md", "02-mock-two.md", "03-mock-report.md"]
    engine = MagicMock(spec=Engine)
    call_state = {"n": 0}

    def execute_side_effect(prompt, working_directory, output_dir):
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
    def execute_side_effect(prompt, working_directory, output_dir):
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


def test_mock_pack_context_accumulates(tmp_path):
    """Prior outputs accumulate across stages when using a non-PASTA pack."""
    mock_pack = _make_mock_pack()
    all_files = ["01-mock-one.md", "02-mock-two.md", "03-mock-report.md"]
    captured_prompts: list[str] = []
    engine = MagicMock(spec=Engine)
    call_state = {"n": 0}

    def execute_side_effect(prompt, working_directory, output_dir):
        captured_prompts.append(prompt)
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

    # Stage 1 prompt has no prior context
    assert "prior=" in captured_prompts[0]
    # Stage 2 prompt includes stage 1 output
    assert "01-mock-one.md" in captured_prompts[1]
    # Stage 3 (report) prompt includes both prior outputs
    assert "01-mock-one.md" in captured_prompts[2]
    assert "02-mock-two.md" in captured_prompts[2]
