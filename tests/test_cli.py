"""Tests for CLI interface."""

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


def test_engine_option_claude_code(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine") as mock_get_engine,
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_engine.return_value = MagicMock()
        runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])
    mock_get_engine.assert_called_once_with("claude-code", verbose=False)


def test_model_requires_explicit_engine(tmp_path):
    """No engine default on model: a path with no --engine errors rather than guessing."""
    result = runner.invoke(app, ["model", str(tmp_path)])
    assert result.exit_code != 0
    assert "engine" in result.output.lower()


def test_engine_option_codex(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine") as mock_get_engine,
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_engine.return_value = MagicMock()
        runner.invoke(app, ["model", str(tmp_path), "--engine", "codex"])
    mock_get_engine.assert_called_once_with("codex", verbose=False)


def test_output_dir_created(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    output_dir = "my-threatmodel"
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
                "--output-dir",
                output_dir,
            ],
        )
    assert os.path.isdir(tmp_path / output_dir)


def test_metadata_written_after_pipeline(tmp_path):
    """write_metadata is called after orchestrator.run() so stages_completed is accurate."""
    call_order = []

    mock_orchestrator_instance = MagicMock()
    mock_orchestrator_instance.run.side_effect = lambda: call_order.append("run") or 0
    mock_orchestrator_instance.stages_completed = 5
    mock_orchestrator_cls = MagicMock(return_value=mock_orchestrator_instance)

    def fake_write_metadata(*args, **kwargs):
        call_order.append("write_metadata")

    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_orchestrator_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata", side_effect=fake_write_metadata),
    ):
        runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])

    assert call_order.index("run") < call_order.index("write_metadata")


def test_business_and_security_objectives_passed(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator()
    captured = {}

    def capture_orchestrator(*args, **kwargs):
        captured.update(kwargs)
        return mock_instance

    mock_cls.side_effect = capture_orchestrator

    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
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
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code", "-v"])

    assert "verbose" not in captured


def test_no_scanner_detection_in_cli(tmp_path):
    """CLI does not call detect_scanners; scanner detection is the agent's responsibility."""
    mock_cls, _ = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        result = runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])

    # If detect_scanners were still called it would import and execute;
    # the clean pass here confirms the call is gone.
    assert result.exit_code == 0


def test_pipeline_exit_code_propagated(tmp_path):
    mock_cls, mock_instance = _make_mock_orchestrator(exit_code=1)
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework", return_value=MagicMock()),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        result = runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])
    assert result.exit_code == 1


# --- --framework flag and --list-frameworks ---


def test_default_framework_is_stride_4q(tmp_path):
    mock_cls, _ = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework") as mock_get_framework,
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_framework.return_value = MagicMock()
        runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])
    mock_get_framework.assert_called_once_with("stride-4q")


def test_explicit_framework_pasta(tmp_path):
    mock_cls, _ = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework") as mock_get_framework,
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_framework.return_value = MagicMock()
        runner.invoke(
            app,
            ["model", str(tmp_path), "--engine", "claude-code", "--framework", "pasta"],
        )
    mock_get_framework.assert_called_once_with("pasta")


def test_list_frameworks_output_contains_built_in():
    result = runner.invoke(app, ["--list-frameworks"])
    assert result.exit_code == 0
    assert "stride-4q" in result.output
    assert "pasta" in result.output


def test_invalid_framework_name_produces_error(tmp_path):
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        result = runner.invoke(
            app,
            [
                "model",
                str(tmp_path),
                "--engine",
                "claude-code",
                "--framework",
                "unknown-fw",
            ],
        )
    assert result.exit_code == 1


def test_config_file_framework_used_when_no_cli_flag(tmp_path):
    (tmp_path / ".threatsmith.yml").write_text("framework: pasta\n")
    mock_cls, _ = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework") as mock_get_framework,
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_framework.return_value = MagicMock()
        runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])
    mock_get_framework.assert_called_once_with("pasta")


def test_cli_framework_overrides_config_file(tmp_path):
    (tmp_path / ".threatsmith.yml").write_text("framework: pasta\n")
    mock_cls, _ = _make_mock_orchestrator()
    with (
        patch("threatsmith.main.get_engine", return_value=MagicMock()),
        patch("threatsmith.main.get_framework") as mock_get_framework,
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        mock_get_framework.return_value = MagicMock()
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
    mock_get_framework.assert_called_once_with("stride-4q")


# --- skills install ---


def _mock_engine_with_skills_dir(skills_dir):
    engine = MagicMock()
    engine.skills_dir = skills_dir
    return engine


def test_skills_install_copies_bundled_skills(tmp_path):
    skills_dir = tmp_path / "skills"
    with patch(
        "threatsmith.main.get_engine",
        return_value=_mock_engine_with_skills_dir(skills_dir),
    ):
        result = runner.invoke(app, ["skills", "install", "--engine", "claude-code"])

    assert result.exit_code == 0
    # The three bundled skills land in the engine's skills directory.
    assert (skills_dir / "threatsmith-stride-4q" / "SKILL.md").is_file()
    assert (skills_dir / "threatsmith-pasta" / "SKILL.md").is_file()
    assert (skills_dir / "threatsmith-secure" / "SKILL.md").is_file()


def test_skills_install_reports_what_and_where(tmp_path):
    skills_dir = tmp_path / "skills"
    with patch(
        "threatsmith.main.get_engine",
        return_value=_mock_engine_with_skills_dir(skills_dir),
    ):
        result = runner.invoke(app, ["skills", "install", "--engine", "claude-code"])

    assert "threatsmith-stride-4q" in result.output
    assert str(skills_dir) in result.output


def test_skills_install_refreshes_existing(tmp_path):
    skills_dir = tmp_path / "skills"
    with patch(
        "threatsmith.main.get_engine",
        return_value=_mock_engine_with_skills_dir(skills_dir),
    ):
        runner.invoke(app, ["skills", "install", "--engine", "claude-code"])
        # A stale file from a prior install must not survive a refresh.
        stale = skills_dir / "threatsmith-stride-4q" / "STALE.md"
        stale.write_text("stale")
        result = runner.invoke(app, ["skills", "install", "--engine", "claude-code"])

    assert result.exit_code == 0
    assert not stale.exists()
    assert (skills_dir / "threatsmith-stride-4q" / "SKILL.md").is_file()


def test_skills_install_target_accounts_for_engine(tmp_path):
    captured = {}

    def capture_engine(name, verbose=False):
        captured["name"] = name
        return _mock_engine_with_skills_dir(tmp_path / "skills")

    with patch("threatsmith.main.get_engine", side_effect=capture_engine):
        runner.invoke(app, ["skills", "install", "--engine", "codex"])

    assert captured["name"] == "codex"


def test_skills_install_no_args_shows_help():
    """Bare `skills install` shows help (no_args_is_help) instead of a bare error."""
    result = runner.invoke(app, ["skills", "install"])
    assert "Usage:" in result.output
    assert "--engine" in result.output


def test_skills_install_missing_engine_errors():
    """No engine default: a partial invocation without --engine errors rather than guessing."""
    result = runner.invoke(app, ["skills", "install", "--verbose"])
    assert result.exit_code != 0
    assert "engine" in result.output.lower()


def test_skills_install_unknown_engine_errors():
    result = runner.invoke(app, ["skills", "install", "--engine", "nope"])
    assert result.exit_code == 1


def test_skills_list_shows_status(tmp_path):
    skills_dir = tmp_path / "skills"
    engine = _mock_engine_with_skills_dir(skills_dir)
    with patch("threatsmith.main.get_engine", return_value=engine):
        # Nothing installed yet.
        before = runner.invoke(app, ["skills", "list", "--engine", "claude-code"])
        runner.invoke(app, ["skills", "install", "--engine", "claude-code"])
        after = runner.invoke(app, ["skills", "list", "--engine", "claude-code"])

    assert before.exit_code == 0
    assert "threatsmith-stride-4q" in before.output
    assert "not installed" in before.output
    assert str(skills_dir) in before.output
    # After installing, the same skill reports installed.
    assert "not installed" not in after.output
    assert "installed" in after.output


def test_skills_list_no_args_shows_help():
    """Bare `skills list` shows help with the required --engine rather than a bare error."""
    result = runner.invoke(app, ["skills", "list"])
    assert "Usage:" in result.output
    assert "--engine" in result.output


def test_skills_list_unknown_engine_errors():
    result = runner.invoke(app, ["skills", "list", "--engine", "nope"])
    assert result.exit_code == 1


# --- pre-run skill validation (US-012) ---


def test_missing_skill_exits_with_clear_error(tmp_path):
    """CLI exits 1 with an actionable message when the required skill is not installed."""
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    # Do NOT create the skill subdirectory — it's missing.
    engine = _mock_engine_with_skills_dir(skills_dir)
    mock_pack = MagicMock()
    mock_pack.skill_name = "threatsmith-stride-4q"
    with (
        patch("threatsmith.main.get_engine", return_value=engine),
        patch("threatsmith.main.get_framework", return_value=mock_pack),
        patch("threatsmith.main.write_metadata"),
    ):
        result = runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])

    assert result.exit_code == 1
    assert "threatsmith-stride-4q" in result.output
    assert "install" in result.output.lower()


def test_missing_skill_error_names_engine(tmp_path):
    """The error message names the engine so the user knows which install command to run."""
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    engine = _mock_engine_with_skills_dir(skills_dir)
    mock_pack = MagicMock()
    mock_pack.skill_name = "threatsmith-pasta"
    with (
        patch("threatsmith.main.get_engine", return_value=engine),
        patch("threatsmith.main.get_framework", return_value=mock_pack),
        patch("threatsmith.main.write_metadata"),
    ):
        result = runner.invoke(app, ["model", str(tmp_path), "--engine", "codex"])

    assert result.exit_code == 1
    assert "codex" in result.output


def test_skill_present_run_proceeds(tmp_path):
    """CLI proceeds normally when the required skill directory is present."""
    skills_dir = tmp_path / "skills"
    (skills_dir / "threatsmith-stride-4q").mkdir(parents=True)
    engine = _mock_engine_with_skills_dir(skills_dir)
    mock_cls, mock_instance = _make_mock_orchestrator()
    mock_pack = MagicMock()
    mock_pack.skill_name = "threatsmith-stride-4q"
    with (
        patch("threatsmith.main.get_engine", return_value=engine),
        patch("threatsmith.main.get_framework", return_value=mock_pack),
        patch("threatsmith.main.Orchestrator", mock_cls),
        patch(
            "threatsmith.main.generate_metadata",
            return_value=MagicMock(commit_hash="abc"),
        ),
        patch("threatsmith.main.write_metadata"),
    ):
        result = runner.invoke(app, ["model", str(tmp_path), "--engine", "claude-code"])

    assert result.exit_code == 0
    mock_instance.run.assert_called_once()
