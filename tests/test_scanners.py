from unittest.mock import patch

from threatsmith.utils.scanners import detect_scanners


def test_detect_scanners_all_available():
    with patch("shutil.which") as mock_which:
        mock_which.return_value = "/usr/bin/scanner"
        result = detect_scanners()

    assert result["available"] == ["semgrep", "trivy", "gitleaks"]
    assert result["unavailable"] == []


def test_detect_scanners_none_available():
    with patch("shutil.which") as mock_which:
        mock_which.return_value = None
        result = detect_scanners()

    assert result["available"] == []
    assert result["unavailable"] == ["semgrep", "trivy", "gitleaks"]


def test_detect_scanners_mixed_availability():
    def mock_which_impl(cmd):
        return "/usr/bin/semgrep" if cmd == "semgrep" else None

    with patch("shutil.which", side_effect=mock_which_impl):
        result = detect_scanners()

    assert result["available"] == ["semgrep"]
    assert result["unavailable"] == ["trivy", "gitleaks"]


def test_detect_scanners_only_trivy_available():
    def mock_which_impl(cmd):
        return "/usr/bin/trivy" if cmd == "trivy" else None

    with patch("shutil.which", side_effect=mock_which_impl):
        result = detect_scanners()

    assert result["available"] == ["trivy"]
    assert result["unavailable"] == ["semgrep", "gitleaks"]


def test_detect_scanners_only_gitleaks_available():
    def mock_which_impl(cmd):
        return "/usr/bin/gitleaks" if cmd == "gitleaks" else None

    with patch("shutil.which", side_effect=mock_which_impl):
        result = detect_scanners()

    assert result["available"] == ["gitleaks"]
    assert result["unavailable"] == ["semgrep", "trivy"]


def test_detect_scanners_semgrep_and_trivy_available():
    def mock_which_impl(cmd):
        return f"/usr/bin/{cmd}" if cmd in ["semgrep", "trivy"] else None

    with patch("shutil.which", side_effect=mock_which_impl):
        result = detect_scanners()

    assert result["available"] == ["semgrep", "trivy"]
    assert result["unavailable"] == ["gitleaks"]


def test_detect_scanners_returns_dict():
    with patch("shutil.which", return_value=None):
        result = detect_scanners()

    assert isinstance(result, dict)
    assert "available" in result
    assert "unavailable" in result
    assert isinstance(result["available"], list)
    assert isinstance(result["unavailable"], list)


def test_detect_scanners_checks_each_scanner():
    with patch("shutil.which") as mock_which:
        mock_which.return_value = None
        detect_scanners()

    assert mock_which.call_count == 3
    calls = [call.args[0] for call in mock_which.call_args_list]
    assert "semgrep" in calls
    assert "trivy" in calls
    assert "gitleaks" in calls
