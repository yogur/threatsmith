"""Build step: sync shared references into each skill and write self-contained skills."""

import shutil
from pathlib import Path

SKILL_SHARED_REFS: dict[str, list[str]] = {
    "threatsmith-stride-4q": [
        "owasp-web-top-10.md",
        "owasp-api-top-10.md",
        "owasp-llm-top-10.md",
        "owasp-mobile-top-10.md",
        "scanners.md",
    ],
    "threatsmith-pasta": [
        "owasp-web-top-10.md",
        "owasp-api-top-10.md",
        "owasp-llm-top-10.md",
        "owasp-mobile-top-10.md",
        "scanners.md",
    ],
    "threatsmith-secure": [],
}


def build_skills(src_root: Path, out_root: Path) -> None:
    """Assemble self-contained skills from sources, syncing shared references in.

    src_root: path to the skills-src/ directory (contains _shared/ and skill dirs)
    out_root: path to write built skills (e.g. build/skills/)
    """
    shared_refs_dir = src_root / "_shared" / "references"

    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True)

    for skill_name, shared_refs in SKILL_SHARED_REFS.items():
        skill_src = src_root / skill_name
        skill_out = out_root / skill_name

        shutil.copytree(skill_src, skill_out)

        if shared_refs:
            refs_out = skill_out / "references"
            refs_out.mkdir(exist_ok=True)
            for ref_file in shared_refs:
                shutil.copy2(shared_refs_dir / ref_file, refs_out / ref_file)
