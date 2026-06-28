"""Runtime accessor for skills bundled as package data."""

from importlib.resources import files as _pkg_files
from pathlib import Path


def get_bundled_skills_path() -> Path:
    """Return the path to the built skills bundled with this package.

    In an installed wheel the skills live at ``threatsmith/_skills/`` (placed
    there by the hatchling ``force-include`` configuration).  In a dev /
    editable install that directory doesn't exist; we fall back to
    ``build/skills/`` in the repository root, which is the committed artifact
    rebuilt by ``make build-skills``.
    """
    pkg_skills = Path(str(_pkg_files("threatsmith") / "_skills"))
    if pkg_skills.is_dir():
        return pkg_skills

    # Editable-install fallback: __file__ is src/threatsmith/_skills_data.py
    dev_skills = Path(__file__).parent.parent.parent / "build" / "skills"
    if dev_skills.is_dir():
        return dev_skills

    raise FileNotFoundError(
        "Bundled skills not found. Run 'make build-skills' to generate build/skills/."
    )
