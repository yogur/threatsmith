"""Install bundled skills into an engine's skills directory."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from threatsmith._skills_data import get_bundled_skills_path


@dataclass(frozen=True)
class InstalledSkill:
    """One skill that was copied into the target skills directory."""

    name: str
    destination: Path


@dataclass(frozen=True)
class SkillStatus:
    """A bundled skill and whether it is installed in a target directory."""

    name: str
    installed: bool
    destination: Path


def list_skill_statuses(
    skills_dir: Path, source: Path | None = None
) -> list[SkillStatus]:
    """Report each bundled skill and whether it is installed in ``skills_dir``.

    ``source`` defaults to the package's bundled skills. A skill counts as
    installed when ``skills_dir/<skill-name>`` exists as a directory. Returns
    the statuses in name order.
    """
    src = source if source is not None else get_bundled_skills_path()
    statuses: list[SkillStatus] = []
    for skill_src in sorted(p for p in src.iterdir() if p.is_dir()):
        dest = skills_dir / skill_src.name
        statuses.append(
            SkillStatus(name=skill_src.name, installed=dest.is_dir(), destination=dest)
        )
    return statuses


def install_skills(
    skills_dir: Path, source: Path | None = None
) -> list[InstalledSkill]:
    """Copy each bundled skill into ``skills_dir``, refreshing existing installs.

    ``source`` defaults to the package's bundled skills. Each skill directory is
    copied to ``skills_dir/<skill-name>``; an existing install of that skill is
    removed first so the copy is a clean refresh (other skills in ``skills_dir``
    are left untouched). Returns the skills installed, in name order.
    """
    src = source if source is not None else get_bundled_skills_path()
    skills_dir.mkdir(parents=True, exist_ok=True)

    installed: list[InstalledSkill] = []
    for skill_src in sorted(p for p in src.iterdir() if p.is_dir()):
        dest = skills_dir / skill_src.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(skill_src, dest)
        installed.append(InstalledSkill(name=skill_src.name, destination=dest))
    return installed
