"""Tests for the skill build step (US-006)."""

import shutil
from pathlib import Path

import pytest

from threatsmith._build_skills import SKILL_SHARED_REFS, build_skills

_REPO_ROOT = Path(__file__).parent.parent
_SKILLS_SRC = _REPO_ROOT / "skills-src"
_SHARED_REFS = _SKILLS_SRC / "_shared" / "references"


@pytest.fixture()
def out_dir(tmp_path: Path) -> Path:
    return tmp_path / "built-skills"


class TestBuildSkillsOutput:
    def test_creates_output_directory(self, out_dir: Path) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        assert out_dir.is_dir()

    def test_all_skills_present(self, out_dir: Path) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        for skill_name in SKILL_SHARED_REFS:
            assert (out_dir / skill_name).is_dir(), f"{skill_name} missing from build"

    def test_skill_md_present_for_each_skill(self, out_dir: Path) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        for skill_name in SKILL_SHARED_REFS:
            assert (out_dir / skill_name / "SKILL.md").is_file()

    def test_stride4q_stage_files_present(self, out_dir: Path) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        stages_dir = out_dir / "threatsmith-stride-4q" / "references" / "stages"
        expected = [
            "01-system-model.md",
            "02-threat-identification.md",
            "03-mitigations.md",
            "04-validation.md",
            "05-report.md",
        ]
        for fname in expected:
            assert (stages_dir / fname).is_file(), f"Missing stride-4q stage: {fname}"

    def test_pasta_stage_files_present(self, out_dir: Path) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        stages_dir = out_dir / "threatsmith-pasta" / "references" / "stages"
        expected = [
            "01-objectives.md",
            "02-technical-scope.md",
            "03-application-decomposition.md",
            "04-threat-analysis.md",
            "05-vulnerability-analysis.md",
            "06-attack-modeling.md",
            "07-risk-and-impact-analysis.md",
            "08-report.md",
        ]
        for fname in expected:
            assert (stages_dir / fname).is_file(), f"Missing PASTA stage: {fname}"


class TestSharedReferenceSync:
    @pytest.mark.parametrize(
        "skill_name",
        ["threatsmith-stride-4q", "threatsmith-pasta"],
    )
    def test_shared_refs_synced_into_framework_skill(
        self, out_dir: Path, skill_name: str
    ) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        refs_dir = out_dir / skill_name / "references"
        for ref_file in SKILL_SHARED_REFS[skill_name]:
            assert (refs_dir / ref_file).is_file(), (
                f"{ref_file} missing from {skill_name}"
            )

    def test_secure_skill_has_no_shared_refs(self, out_dir: Path) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        assert SKILL_SHARED_REFS["threatsmith-secure"] == []
        secure_dir = out_dir / "threatsmith-secure"
        # only SKILL.md — no references/ dir
        assert (secure_dir / "SKILL.md").is_file()
        refs_dir = secure_dir / "references"
        assert not refs_dir.exists()

    @pytest.mark.parametrize(
        "skill_name",
        ["threatsmith-stride-4q", "threatsmith-pasta"],
    )
    def test_only_declared_refs_synced(self, out_dir: Path, skill_name: str) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        refs_dir = out_dir / skill_name / "references"
        built_refs = {f.name for f in refs_dir.iterdir() if f.is_file()}
        expected = set(SKILL_SHARED_REFS[skill_name])
        # may also include stage files (in subdirs, not direct files)
        assert expected <= built_refs
        # no extra shared refs beyond what's declared
        assert built_refs == expected

    def test_shared_ref_content_matches_canonical(self, out_dir: Path) -> None:
        build_skills(_SKILLS_SRC, out_dir)
        ref_file = "owasp-web-top-10.md"
        canonical = (_SHARED_REFS / ref_file).read_text()
        for skill_name, refs in SKILL_SHARED_REFS.items():
            if ref_file in refs:
                built = (out_dir / skill_name / "references" / ref_file).read_text()
                assert built == canonical, (
                    f"{skill_name}: {ref_file} content differs from canonical"
                )


class TestRebuildUpdatesSkills:
    def test_editing_canonical_ref_and_rebuilding_updates_built_skill(
        self, out_dir: Path, tmp_path: Path
    ) -> None:
        # Set up a temp skills-src copy so we don't modify the real source
        temp_src = tmp_path / "skills-src"
        shutil.copytree(_SKILLS_SRC, temp_src)

        build_skills(temp_src, out_dir)

        canonical_ref = temp_src / "_shared" / "references" / "owasp-web-top-10.md"
        original = canonical_ref.read_text()
        modified = original + "\n<!-- test-marker -->"
        canonical_ref.write_text(modified)

        build_skills(temp_src, out_dir)

        for skill_name, refs in SKILL_SHARED_REFS.items():
            if "owasp-web-top-10.md" in refs:
                built = (
                    out_dir / skill_name / "references" / "owasp-web-top-10.md"
                ).read_text()
                assert "test-marker" in built, (
                    f"{skill_name}: rebuild did not update owasp-web-top-10.md"
                )

    def test_rebuild_clears_stale_artifacts(
        self, out_dir: Path, tmp_path: Path
    ) -> None:
        temp_src = tmp_path / "skills-src"
        shutil.copytree(_SKILLS_SRC, temp_src)

        build_skills(temp_src, out_dir)
        stale_file = out_dir / "threatsmith-stride-4q" / "references" / "stale.md"
        stale_file.write_text("stale")

        build_skills(temp_src, out_dir)
        assert not stale_file.exists()


class TestCommittedArtifacts:
    def test_committed_build_matches_fresh_build(self, out_dir: Path) -> None:
        """Fresh build output must be identical to the committed build/skills/."""
        committed = _REPO_ROOT / "build" / "skills"
        build_skills(_SKILLS_SRC, out_dir)

        committed_files = {
            f.relative_to(committed) for f in committed.rglob("*") if f.is_file()
        }
        built_files = {
            f.relative_to(out_dir) for f in out_dir.rglob("*") if f.is_file()
        }
        assert committed_files == built_files, (
            "File set mismatch between committed build/skills/ and fresh build. "
            "Run: uv run python scripts/build_skills.py"
        )

        for rel in committed_files:
            committed_content = (committed / rel).read_text()
            built_content = (out_dir / rel).read_text()
            assert committed_content == built_content, (
                f"Content mismatch for {rel}. "
                "Run: uv run python scripts/build_skills.py"
            )
