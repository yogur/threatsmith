"""Tests for 4QF+STRIDE Stage 4 — Validation prompt template."""

from threatsmith.frameworks.stride_4q.stage_04_validation import (
    STAGE_PROMPT,
    build_prompt,
)
from threatsmith.frameworks.types import StageContext


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(StageContext())
        assert isinstance(result, str)

    def test_with_all_three_prior_stages(self):
        """Verify prompt includes Stages 1, 2, and 3 outputs."""
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "## System Model\nComponents...",
                    "stage_02_output": "## Threats\nSpoofing threat...",
                    "stage_03_output": "## Mitigations\nCountermeasures...",
                }
            )
        )
        assert "## System Model" in result
        assert "Components..." in result
        assert "## Threats" in result
        assert "Spoofing threat..." in result
        assert "## Mitigations" in result
        assert "Countermeasures..." in result

    def test_prior_stage_01_injected(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "System model content"})
        )
        assert "PRIOR STAGE FINDINGS" in result
        assert "<stage_01_system_model>" in result
        assert "System model content" in result
        assert "</stage_01_system_model>" in result

    def test_prior_stage_02_injected(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_02_output": "Threat inventory content"})
        )
        assert "PRIOR STAGE FINDINGS" in result
        assert "<stage_02_threat_identification>" in result
        assert "Threat inventory content" in result
        assert "</stage_02_threat_identification>" in result

    def test_prior_stage_03_injected(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_03_output": "Mitigation plan content"})
        )
        assert "PRIOR STAGE FINDINGS" in result
        assert "<stage_03_mitigations>" in result
        assert "Mitigation plan content" in result
        assert "</stage_03_mitigations>" in result

    def test_prior_stages_absent_when_no_output(self):
        result = build_prompt(StageContext())
        assert "PRIOR STAGE FINDINGS" not in result
        assert "<stage_01_system_model>" not in result
        assert "<stage_02_threat_identification>" not in result
        assert "<stage_03_mitigations>" not in result

    def test_prior_stage_01_absent_when_empty_string(self):
        result = build_prompt(StageContext(prior_outputs={"stage_01_output": ""}))
        assert "<stage_01_system_model>" not in result

    def test_prior_stage_02_absent_when_empty_string(self):
        result = build_prompt(StageContext(prior_outputs={"stage_02_output": ""}))
        assert "<stage_02_threat_identification>" not in result

    def test_prior_stage_03_absent_when_empty_string(self):
        result = build_prompt(StageContext(prior_outputs={"stage_03_output": ""}))
        assert "<stage_03_mitigations>" not in result

    def test_only_stage_01_present(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "Model only"})
        )
        assert "<stage_01_system_model>" in result
        assert "<stage_02_threat_identification>" not in result
        assert "<stage_03_mitigations>" not in result

    def test_only_stage_03_present(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_03_output": "Mitigations only"})
        )
        assert "<stage_03_mitigations>" in result
        assert "<stage_01_system_model>" not in result
        assert "<stage_02_threat_identification>" not in result

    def test_output_file_path(self):
        result = build_prompt(StageContext())
        assert "threatmodel/04-validation.md" in result

    def test_custom_output_dir(self):
        result = build_prompt(StageContext(), output_dir="output")
        assert "output/04-validation.md" in result

    def test_output_dir_trailing_slash_normalized(self):
        result = build_prompt(StageContext(), output_dir="output/")
        assert "output/04-validation.md" in result
        assert "output//04-validation.md" not in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(StageContext())
        assert "{prior_stages_section}" not in result
        assert "{output_dir}" not in result

    def test_contains_four_question_framework_context(self):
        result = build_prompt(StageContext())
        assert "Did we do a good job?" in result

    def test_covers_component_coverage_verification(self):
        result = build_prompt(StageContext())
        assert "Component Coverage" in result

    def test_covers_stride_category_coverage_verification(self):
        result = build_prompt(StageContext())
        assert "STRIDE Category Coverage" in result or "STRIDE Coverage" in result

    def test_covers_mitigation_completeness(self):
        result = build_prompt(StageContext())
        assert "Mitigation Completeness" in result or "Mitigation Adequacy" in result

    def test_covers_remaining_gaps(self):
        result = build_prompt(StageContext())
        assert "Remaining Gaps" in result or "remaining gaps" in result

    def test_covers_accepted_risks(self):
        result = build_prompt(StageContext())
        assert "Accepted Risks" in result or "accepted risks" in result

    def test_covers_review_cadence(self):
        result = build_prompt(StageContext())
        assert "review cadence" in result.lower()

    def test_covers_next_steps(self):
        result = build_prompt(StageContext())
        assert "Next Steps" in result or "next steps" in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholders(self):
        assert "{prior_stages_section}" in STAGE_PROMPT
        assert "{output_dir}" in STAGE_PROMPT
