"""
Built-in framework pack registrations.

Each framework registers itself here. Importing this module is sufficient to register all
four frameworks.
"""

from threatsmith.frameworks.pasta import build_pasta_pack
from threatsmith.frameworks.types import FrameworkPack, StageSpec, register_framework


def _placeholder_build_prompt(context: dict) -> str:  # pragma: no cover
    return ""


def _placeholder_stage(number: int, name: str, output_file: str) -> StageSpec:
    return StageSpec(
        number=number,
        name=name,
        output_file=output_file,
        build_prompt=_placeholder_build_prompt,
    )


register_framework(
    FrameworkPack(
        name="stride-4q",
        display_name="4QF + STRIDE",
        description=(
            "Four Question Framework with STRIDE. Lightweight, fast, good default "
            "for most codebases."
        ),
        stages=[],
        report_stage=_placeholder_stage(5, "Report", "05-report.md"),
    )
)

register_framework(build_pasta_pack())

register_framework(
    FrameworkPack(
        name="linddun",
        display_name="LINDDUN Pro",
        description=(
            "Systematic privacy threat modeling for codebases handling personal "
            "data under GDPR, HIPAA, or similar regulations."
        ),
        stages=[],
        report_stage=_placeholder_stage(6, "Report", "06-report.md"),
    )
)

register_framework(
    FrameworkPack(
        name="maestro",
        display_name="MAESTRO",
        description=(
            "AI/ML system threat modeling for codebases that include models, "
            "training pipelines, inference services, or autonomous agents."
        ),
        stages=[],
        report_stage=_placeholder_stage(7, "Report", "07-report.md"),
    )
)
