"""Framework packs — thin orchestration metadata for each threat-modeling methodology.

Under Model B a methodology's prompt content lives in an installed Agent Skill, not in
Python. A "framework" here is just the metadata the CLI needs to drive a run: the ordered
stage list, the expected output filenames, the report stage, and the name of the skill
that provides the content. The two built-in packs register themselves at import time.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StageSpec:
    number: int
    name: str
    output_file: str


@dataclass(frozen=True)
class FrameworkPack:
    name: str
    display_name: str
    description: str
    stages: list[StageSpec]
    report_stage: StageSpec
    skill_name: str = ""


_REGISTRY: dict[str, FrameworkPack] = {}


def register_framework(pack: FrameworkPack) -> None:
    """Register a framework pack so the CLI can resolve it by name."""
    _REGISTRY[pack.name] = pack


def get_framework(name: str) -> FrameworkPack:
    if name in _REGISTRY:
        return _REGISTRY[name]
    available = ", ".join(sorted(_REGISTRY.keys()))
    raise ValueError(f"Unknown framework '{name}'. Available frameworks: {available}")


def list_frameworks() -> list[FrameworkPack]:
    return list(_REGISTRY.values())


# --- Built-in framework packs ------------------------------------------------

STRIDE_4Q = FrameworkPack(
    name="stride-4q",
    display_name="4QF + STRIDE",
    skill_name="threatsmith-stride-4q",
    description=(
        "Four Question Framework with STRIDE. Lightweight, fast, good default "
        "for most codebases."
    ),
    stages=[
        StageSpec(number=1, name="System Model", output_file="01-system-model.md"),
        StageSpec(
            number=2,
            name="Threat Identification",
            output_file="02-threat-identification.md",
        ),
        StageSpec(number=3, name="Mitigations", output_file="03-mitigations.md"),
        StageSpec(number=4, name="Validation", output_file="04-validation.md"),
    ],
    report_stage=StageSpec(number=5, name="Report", output_file="05-report.md"),
)

PASTA = FrameworkPack(
    name="pasta",
    display_name="PASTA",
    skill_name="threatsmith-pasta",
    description=(
        "Process for Attack Simulation and Threat Analysis. Full 7-stage "
        "risk-centric analysis."
    ),
    stages=[
        StageSpec(number=1, name="Define Objectives", output_file="01-objectives.md"),
        StageSpec(
            number=2,
            name="Define Technical Scope",
            output_file="02-technical-scope.md",
        ),
        StageSpec(
            number=3,
            name="Application Decomposition",
            output_file="03-application-decomposition.md",
        ),
        StageSpec(
            number=4, name="Threat Analysis", output_file="04-threat-analysis.md"
        ),
        StageSpec(
            number=5,
            name="Vulnerability and Weakness Analysis",
            output_file="05-vulnerability-analysis.md",
        ),
        StageSpec(
            number=6, name="Attack Modeling", output_file="06-attack-modeling.md"
        ),
        StageSpec(
            number=7,
            name="Risk and Impact Analysis",
            output_file="07-risk-and-impact-analysis.md",
        ),
    ],
    report_stage=StageSpec(number=8, name="Report", output_file="08-report.md"),
)

# LINDDUN Pro and MAESTRO are deferred to a future release.

register_framework(STRIDE_4Q)
register_framework(PASTA)


__all__ = [
    "StageSpec",
    "FrameworkPack",
    "STRIDE_4Q",
    "PASTA",
    "register_framework",
    "get_framework",
    "list_frameworks",
]
