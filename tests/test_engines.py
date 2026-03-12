from unittest.mock import MagicMock, patch

from threatsmith.engines.claude_code import ClaudeCodeEngine


def test_claude_code_engine_constructs_correct_command():
    engine = ClaudeCodeEngine()
    mock_result = MagicMock()
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        exit_code = engine.execute(
            prompt="You are a security analyst.\n\nAnalyze threats.",
            working_directory="/tmp/repo",
        )

    mock_run.assert_called_once()
    call_args = mock_run.call_args
    cmd = call_args.args[0]

    assert cmd[0] == "claude"
    assert cmd[1] == "-p"
    assert cmd[2] == "You are a security analyst.\n\nAnalyze threats."
    assert call_args.kwargs["cwd"] == "/tmp/repo"
    assert exit_code == 0


def test_claude_code_engine_passes_prompt_as_is():
    engine = ClaudeCodeEngine()
    mock_result = MagicMock()
    mock_result.returncode = 0
    prompt = "assembled prompt with all context"

    with patch("subprocess.run", return_value=mock_result) as mock_run:
        engine.execute(prompt=prompt, working_directory="/tmp/repo")

    cmd = mock_run.call_args.args[0]
    assert cmd[2] == prompt


def test_claude_code_engine_returns_exit_code():
    engine = ClaudeCodeEngine()
    mock_result = MagicMock()
    mock_result.returncode = 1

    with patch("subprocess.run", return_value=mock_result):
        exit_code = engine.execute(prompt="prompt", working_directory="/tmp/repo")

    assert exit_code == 1
