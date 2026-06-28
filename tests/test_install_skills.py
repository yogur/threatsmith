"""Tests for the skill installer."""

from __future__ import annotations

from threatsmith._install_skills import (
    InstalledSkill,
    install_skills,
    list_skill_statuses,
)


def _make_source(root):
    """Build a fake bundled-skills source tree under root."""
    skill_a = root / "skill-a"
    (skill_a / "references").mkdir(parents=True)
    (skill_a / "SKILL.md").write_text("a")
    (skill_a / "references" / "ref.md").write_text("ref")
    skill_b = root / "skill-b"
    skill_b.mkdir()
    (skill_b / "SKILL.md").write_text("b")
    (root / "loose-file.txt").write_text("ignored")  # non-dir entries skipped
    return root


def test_install_copies_each_skill_dir(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"

    installed = install_skills(target, source=source)

    assert {s.name for s in installed} == {"skill-a", "skill-b"}
    assert (target / "skill-a" / "SKILL.md").read_text() == "a"
    assert (target / "skill-a" / "references" / "ref.md").read_text() == "ref"
    assert (target / "skill-b" / "SKILL.md").read_text() == "b"


def test_install_skips_non_directory_entries(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"

    install_skills(target, source=source)

    assert not (target / "loose-file.txt").exists()


def test_install_returns_destinations(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"

    installed = install_skills(target, source=source)

    by_name = {s.name: s for s in installed}
    assert isinstance(by_name["skill-a"], InstalledSkill)
    assert by_name["skill-a"].destination == target / "skill-a"


def test_install_creates_target_dir(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "nested" / "skills"

    install_skills(target, source=source)

    assert target.is_dir()


def test_reinstall_refreshes_and_drops_stale_files(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"

    install_skills(target, source=source)
    stale = target / "skill-a" / "stale.md"
    stale.write_text("stale")

    install_skills(target, source=source)

    assert not stale.exists()
    assert (target / "skill-a" / "SKILL.md").read_text() == "a"


def test_reinstall_leaves_unrelated_skills_untouched(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"
    other = target / "someone-elses-skill"
    other.mkdir(parents=True)
    (other / "SKILL.md").write_text("keep me")

    install_skills(target, source=source)

    assert (other / "SKILL.md").read_text() == "keep me"


def test_list_statuses_reports_not_installed_before_install(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"

    statuses = list_skill_statuses(target, source=source)

    by_name = {s.name: s for s in statuses}
    assert set(by_name) == {"skill-a", "skill-b"}
    assert all(not s.installed for s in statuses)
    assert by_name["skill-a"].destination == target / "skill-a"


def test_list_statuses_reflects_installed_skills(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"
    install_skills(target, source=source)

    statuses = list_skill_statuses(target, source=source)

    assert all(s.installed for s in statuses)


def test_list_statuses_partial_install(tmp_path):
    source = _make_source(tmp_path / "src")
    target = tmp_path / "skills"
    # Only skill-a is present in the target.
    (target / "skill-a").mkdir(parents=True)

    statuses = {s.name: s.installed for s in list_skill_statuses(target, source=source)}

    assert statuses == {"skill-a": True, "skill-b": False}
