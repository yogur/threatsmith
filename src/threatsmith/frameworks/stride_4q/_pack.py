"""4QF+STRIDE framework pack builder."""

from threatsmith.frameworks.references.owasp import (
    OWASP_API_TOP_10,
    OWASP_LLM_TOP_10,
    OWASP_MOBILE_TOP_10,
    OWASP_WEB_TOP_10,
)
from threatsmith.frameworks.references.stride_categories import STRIDE_CATEGORIES
from threatsmith.frameworks.stride_4q import (
    stage_01_system_model,
    stage_02_threat_identification,
    stage_03_mitigations,
    stage_04_validation,
    stage_05_report,
)
from threatsmith.frameworks.types import FrameworkPack, StageSpec


def build_stride_4q_pack() -> FrameworkPack:
    """Build and return the 4QF+STRIDE framework pack."""
    return FrameworkPack(
        name="stride-4q",
        display_name="4QF + STRIDE",
        description=(
            "Four Question Framework with STRIDE. Lightweight, fast, good default "
            "for most codebases."
        ),
        stages=[
            StageSpec(
                number=1,
                name="System Model",
                output_file="01-system-model.md",
                build_prompt=stage_01_system_model.build_prompt,
            ),
            StageSpec(
                number=2,
                name="Threat Identification",
                output_file="02-threat-identification.md",
                build_prompt=stage_02_threat_identification.build_prompt,
            ),
            StageSpec(
                number=3,
                name="Mitigations",
                output_file="03-mitigations.md",
                build_prompt=stage_03_mitigations.build_prompt,
            ),
            StageSpec(
                number=4,
                name="Validation",
                output_file="04-validation.md",
                build_prompt=stage_04_validation.build_prompt,
            ),
        ],
        report_stage=StageSpec(
            number=5,
            name="Report",
            output_file="05-report.md",
            build_prompt=stage_05_report.build_prompt,
        ),
        scanner_stages=[2],
        reference_sets={
            2: [
                {"condition": "always", "reference": STRIDE_CATEGORIES},
                {"condition": "always", "reference": OWASP_WEB_TOP_10},
                {"condition": "api_detected", "reference": OWASP_API_TOP_10},
                {"condition": "llm_detected", "reference": OWASP_LLM_TOP_10},
                {"condition": "mobile_detected", "reference": OWASP_MOBILE_TOP_10},
            ]
        },
    )
