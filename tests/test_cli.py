"""Tests for CLI interface (US-017)."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from threatsmith.main import app

runner = CliRunner()


def _make_mock_orchestrator(exit_code: int = 0):
    """Return a mock Orchestrator class whose run() returns exit_code."""
    mock_instance = MagicMock()
    mock_instance.run.return_value = exit_code
    mock_cls = MagicMock(return_value=mock_instance)
    return mock_cls, mock_instance


def test_help_includes_all_options():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "--engine" in result.output
    assert "--business-objectives" in result.output
    assert "--security-objectives" in result.output
    assert "--output-dir" in result.output
    assert "--verbose" in result.output or "-v" in result.output
    assert "PATH" in result.output.upper() or "path" in result.output


def test_default_engine_is_claude_code(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine") as mock_get_engine,
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": [], "unavailable": []},
        ),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_engine.return_value = MagicMock()
        runner.invoke(app, [str(tmp_path)])
    mock_get_engine.assert_called_once_with("claude-code")


def test_engine_option_codex(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine") as mock_get_engine,
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": [], "unavailable": []},
        ),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_engine.return_value = MagicMock()
        runner.invoke(app, [str(tmp_path), "--engine", "codex"])
    mock_get_engine.assert_called_once_with("codex")


def test_output_dir_created(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    output_dir = "my-threatmodel"
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": [], "unavailable": []},
        ),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        runner.invoke(app, [str(tmp_path), "--output-dir", output_dir])
    assert os.path.isdir(tmp_path / output_dir)


def test_metadata_written_before_pipeline(tmp_path):
    """write_metadata is called before orchestrator.run()."""
    call_order = []

    mock_orchestrator_instance = MagicMock()
    mock_orchestrator_instance.run.side_effect = lambda: call_order.append("run") or 0
    mock_orchestrator_cls = MagicMock(return_value=mock_orchestrator_instance)

    def fake_write_metadata(*args, **kwargs):
        call_order.append("write_metadata")

    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_orchestrator_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": [], "unavailable": []},
        ),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata", side_effect=fake_write_metadata),
    ):
        runner.invoke(app, [str(tmp_path)])

    assert call_order.index("write_metadata") < call_order.index("run")


def test_business_and_security_objectives_passed(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    captured = {}

    def capture_orchestrator(*args, **kwargs):
        captured.update(kwargs)
        return mock_instance

    mock_cls.side_effect = capture_orchestrator

    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": [], "unavailable": []},
        ),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        runner.invoke(
            app,
            [
                str(tmp_path),
                "--business-objectives",
                "protect revenue",
                "--security-objectives",
                "zero trust",
            ],
        )

    user_obj = captured.get("user_objectives", {})
    assert user_obj.get("business_objectives") == "protect revenue"
    assert user_obj.get("security_objectives") == "zero trust"


def test_verbose_flag_not_forwarded_to_orchestrator(tmp_path):
    """The -v flag configures logging directly; it is not forwarded to Orchestrator."""
    mock_cls, mock_instance = _make_mock_orchestrator()
    captured = {}

    def capture_orchestrator(*args, **kwargs):
        captured.update(kwargs)
        return mock_instance

    mock_cls.side_effect = capture_orchestrator

    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": [], "unavailable": []},
        ),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        runner.invoke(app, [str(tmp_path), "-v"])

    assert "verbose" not in captured


def test_detect_scanners_called(tmp_path):
    mock_cls, _ = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": ["semgrep"], "unavailable": []},
        ) as mock_detect,
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        runner.invoke(app, [str(tmp_path)])
    mock_detect.assert_called_once()


def test_pipeline_exit_code_propagated(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator(exit_code=1)
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.detect_scanners",
            return_value={"available": [], "unavailable": []},
        ),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        result = runner.invoke(app, [str(tmp_path)])
    assert result.exit_code == 1
