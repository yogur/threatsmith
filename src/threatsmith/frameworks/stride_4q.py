"""4QF+STRIDE framework pack."""

from threatsmith.frameworks.types import FrameworkPack, StageSpec


def build_stride_4q_pack() -> FrameworkPack:
    """Build and return the 4QF+STRIDE framework pack."""
    return FrameworkPack(
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
