#!/usr/bin/env python3
"""Build self-contained skills from sources.

Usage: uv run python scripts/build_skills.py
"""

from pathlib import Path

from threatsmith._build_skills import build_skills

_REPO_ROOT = Path(__file__).parent.parent


def main() -> None:
    src_root = _REPO_ROOT / "skills-src"
    out_root = _REPO_ROOT / "build" / "skills"
    build_skills(src_root=src_root, out_root=out_root)
    print(f"Built skills written to {out_root.relative_to(_REPO_ROOT)}/")


if __name__ == "__main__":
    main()
