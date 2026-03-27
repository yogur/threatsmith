from unittest.mock import MagicMock, patch

from threatsmith.engines import get_engine
from threatsmith.engines.claude_code import ClaudeCodeEngine
from threatsmith.engines.codex import CodexEngine


def test_claude_code_engine_constructs_correct_command():
    engine = ClaudeCodeEngine()
    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        exit_code = engine.execute(
            prompt="You are a security analyst.\n\nAnalyze threats.",
            working_directory="/tmp/repo",
            output_dir="threatmodel",
        )

    mock_run.assert_called_once()
    call_args = mock_run.call_args
    cmd = call_args.args[0]

    assert cmd[0] == "claude"
    assert cmd[1] == "-p"
    assert cmd[2] == "You are a security analyst.\n\nAnalyze threats."
    assert "--allowedTools" in cmd
    assert "Write(threatmodel/**)" in cmd
    assert "Edit(threatmodel/**)" in cmd
    assert "--verbose" not in cmd
    assert call_args.kwargs["cwd"] == "/tmp/repo"
    assert exit_code == 0


def test_claude_code_engine_verbose_streams_json():
    engine = ClaudeCodeEngine(verbose=True)
    mock_proc = MagicMock()
    mock_proc.stdout = iter([])
    mock_proc.returncode = 0

    with patch("subprocess.Popen", return_value=mock_proc) as mock_popen:
        exit_code = engine.execute(
            prompt="prompt",
            working_directory="/tmp/repo",
            output_dir="threatmodel",
        )

    cmd = mock_popen.call_args.args[0]
    assert "--verbose" in cmd
    assert "--output-format" in cmd
    assert "stream-json" in cmd
    assert "--include-partial-messages" in cmd
    assert exit_code == 0


def test_claude_code_engine_strips_trailing_slash_from_output_dir():
    engine = ClaudeCodeEngine()
    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        engine.execute(
            prompt="prompt", working_directory="/tmp/repo", output_dir="threatmodel/"
        )

    cmd = mock_run.call_args.args[0]
    assert "Write(threatmodel/**)" in cmd
    assert "Edit(threatmodel/**)" in cmd


def test_claude_code_engine_passes_prompt_as_is():
    engine = ClaudeCodeEngine()
    mock_result = MagicMock()
    mock_result.returncode = 0
    prompt = "assembled prompt with all context"

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        engine.execute(
            prompt=prompt, working_directory="/tmp/repo", output_dir="threatmodel"
        )

    cmd = mock_run.call_args.args[0]
    assert cmd[2] == prompt


def test_claude_code_engine_returns_exit_code():
    engine = ClaudeCodeEngine()
    mock_result = MagicMock()
    mock_result.returncode = 1

    with patch("subprocess.run", return_value=mock_result):
        exit_code = engine.execute(
            prompt="prompt", working_directory="/tmp/repo", output_dir="threatmodel"
        )

    assert exit_code == 1


def test_codex_engine_constructs_correct_command():
    engine = CodexEngine()
    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        exit_code = engine.execute(
            prompt="fix the security issue",
            working_directory="/tmp/repo",
            output_dir="threatmodel",
        )

    mock_run.assert_called_once()
    call_args = mock_run.call_args
    cmd = call_args.args[0]

    assert cmd[0] == "codex"
    assert cmd[1] == "exec"
    assert cmd[2] == "fix the security issue"
    assert call_args.kwargs["cwd"] == "/tmp/repo"
    assert exit_code == 0


def test_codex_engine_non_verbose_suppresses_output():
    engine = CodexEngine(verbose=False)
    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        engine.execute(
            prompt="prompt", working_directory="/tmp/repo", output_dir="threatmodel"
        )

    import subprocess

    kwargs = mock_run.call_args.kwargs
    assert kwargs["stdout"] == subprocess.DEVNULL
    assert kwargs["stderr"] == subprocess.DEVNULL


def test_codex_engine_verbose_does_not_suppress_output():
    engine = CodexEngine(verbose=True)
    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        engine.execute(
            prompt="prompt", working_directory="/tmp/repo", output_dir="threatmodel"
        )

    kwargs = mock_run.call_args.kwargs
    assert "stdout" not in kwargs
    assert "stderr" not in kwargs


def test_codex_engine_returns_exit_code():
    engine = CodexEngine()
    mock_result = MagicMock()
    mock_result.returncode = 2

    with patch("subprocess.run", return_value=mock_result):
        exit_code = engine.execute(
            prompt="prompt", working_directory="/tmp/repo", output_dir="threatmodel"
        )

    assert exit_code == 2


def test_get_engine_returns_claude_code_engine():
    engine = get_engine("claude-code")
    assert isinstance(engine, ClaudeCodeEngine)


def test_get_engine_returns_codex_engine():
    engine = get_engine("codex")
    assert isinstance(engine, CodexEngine)


def test_get_engine_raises_for_unknown_engine():
    import pytest

    with pytest.raises(ValueError, match="Unknown engine"):
        get_engine("unknown-engine")
