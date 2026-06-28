"""Tests for bundled-skills package data (US-010)."""

import tomllib
import zipfile
from pathlib import Path

import pytest

from threatsmith._build_skills import SKILL_SHARED_REFS
from threatsmith._skills_data import get_bundled_skills_path

_REPO_ROOT = Path(__file__).parent.parent


class TestGetBundledSkillsPath:
    def test_returns_a_directory(self) -> None:
        assert get_bundled_skills_path().is_dir()

    def test_all_skills_present(self) -> None:
        p = get_bundled_skills_path()
        for skill_name in SKILL_SHARED_REFS:
            assert (p / skill_name).is_dir(), f"{skill_name} missing from bundle"

    def test_each_skill_has_skill_md(self) -> None:
        p = get_bundled_skills_path()
        for skill_name in SKILL_SHARED_REFS:
            assert (p / skill_name / "SKILL.md").is_file(), (
                f"SKILL.md missing from bundled {skill_name}"
            )

    def test_framework_skills_have_stage_refs(self) -> None:
        p = get_bundled_skills_path()
        for skill_name, shared_refs in SKILL_SHARED_REFS.items():
            if shared_refs:
                stages_dir = p / skill_name / "references" / "stages"
                assert stages_dir.is_dir(), (
                    f"references/stages/ missing from bundled {skill_name}"
                )
                assert any(stages_dir.iterdir()), (
                    f"references/stages/ is empty in bundled {skill_name}"
                )


class TestPyprojectForceInclude:
    def test_force_include_configured(self) -> None:
        pyproject = _REPO_ROOT / "pyproject.toml"
        config = tomllib.loads(pyproject.read_text())
        force_include = config["tool"]["hatch"]["build"]["targets"]["wheel"][
            "force-include"
        ]
        assert "build/skills" in force_include, (
            "build/skills not in wheel force-include; bundled skills will be missing"
        )
        assert force_include["build/skills"] == "threatsmith/_skills", (
            "force-include destination must be 'threatsmith/_skills'"
        )


@pytest.mark.slow
class TestWheelContainsBundledSkills:
    """Build an actual wheel and verify the skills are embedded."""

    def test_wheel_contains_skills(self, tmp_path: Path) -> None:
        import subprocess

        result = subprocess.run(
            ["uv", "build", "--wheel", "--out-dir", str(tmp_path)],
            cwd=str(_REPO_ROOT),
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"uv build failed:\n{result.stderr}"

        wheels = list(tmp_path.glob("*.whl"))
        assert wheels, "No wheel produced"

        with zipfile.ZipFile(wheels[0]) as zf:
            names = set(zf.namelist())

        for skill_name in SKILL_SHARED_REFS:
            expected = f"threatsmith/_skills/{skill_name}/SKILL.md"
            assert expected in names, (
                f"{expected} not found in wheel; bundled skills may be missing"
            )
