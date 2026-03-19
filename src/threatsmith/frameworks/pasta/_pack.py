"""PASTA framework pack builder."""

from threatsmith.frameworks.pasta import (
    stage_01_objectives,
    stage_02_technical_scope,
    stage_03_decomposition,
    stage_04_threat_analysis,
    stage_05_vulnerability,
    stage_06_attack_modeling,
    stage_07_risk_impact,
    stage_08_report,
)
from threatsmith.frameworks.references.owasp import (
    OWASP_API_TOP_10,
    OWASP_LLM_TOP_10,
    OWASP_MOBILE_TOP_10,
    OWASP_WEB_TOP_10,
)
from threatsmith.frameworks.types import FrameworkPack, StageSpec


def build_pasta_pack() -> FrameworkPack:
    """Build and return the PASTA framework pack."""
    return FrameworkPack(
        name="pasta",
        display_name="PASTA",
        description=(
            "Process for Attack Simulation and Threat Analysis. Full 7-stage "
            "risk-centric analysis."
        ),
        stages=[
            StageSpec(
                number=1,
                name="Define Objectives",
                output_file="01-objectives.md",
                build_prompt=stage_01_objectives.build_prompt,
            ),
            StageSpec(
                number=2,
                name="Define Technical Scope",
                output_file="02-technical-scope.md",
                build_prompt=stage_02_technical_scope.build_prompt,
            ),
            StageSpec(
                number=3,
                name="Application Decomposition",
                output_file="03-application-decomposition.md",
                build_prompt=stage_03_decomposition.build_prompt,
            ),
            StageSpec(
                number=4,
                name="Threat Analysis",
                output_file="04-threat-analysis.md",
                build_prompt=stage_04_threat_analysis.build_prompt,
            ),
            StageSpec(
                number=5,
                name="Vulnerability and Weakness Analysis",
                output_file="05-vulnerability-analysis.md",
                build_prompt=stage_05_vulnerability.build_prompt,
            ),
            StageSpec(
                number=6,
                name="Attack Modeling",
                output_file="06-attack-modeling.md",
                build_prompt=stage_06_attack_modeling.build_prompt,
            ),
            StageSpec(
                number=7,
                name="Risk and Impact Analysis",
                output_file="07-risk-and-impact-analysis.md",
                build_prompt=stage_07_risk_impact.build_prompt,
            ),
        ],
        report_stage=StageSpec(
            number=8,
            name="Report",
            output_file="08-report.md",
            build_prompt=stage_08_report.build_prompt,
        ),
        scanner_stages=[5],
        reference_sets={
            4: [
                {"condition": "always", "reference": OWASP_WEB_TOP_10},
                {"condition": "api_detected", "reference": OWASP_API_TOP_10},
                {"condition": "llm_detected", "reference": OWASP_LLM_TOP_10},
                {"condition": "mobile_detected", "reference": OWASP_MOBILE_TOP_10},
            ]
        },
    )
