"""PASTA framework pack."""

from threatsmith.frameworks.types import FrameworkPack, StageSpec


def build_pasta_pack() -> FrameworkPack:
    """Build and return the PASTA framework pack."""
    return FrameworkPack(
        name="pasta",
        display_name="PASTA",
        skill_name="threatsmith-pasta",
        description=(
            "Process for Attack Simulation and Threat Analysis. Full 7-stage "
            "risk-centric analysis."
        ),
        stages=[
            StageSpec(
                number=1, name="Define Objectives", output_file="01-objectives.md"
            ),
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
