"""Tests for 4QF+STRIDE Stage 3 — Mitigations prompt template."""

from threatsmith.frameworks.stride_4q.stage_03_mitigations import (
    STAGE_PROMPT,
    build_prompt,
)
from threatsmith.frameworks.types import StageContext


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(StageContext())
        assert isinstance(result, str)

    def test_with_both_prior_stages(self):
        """Verify prompt includes both Stage 1 and Stage 2 outputs."""
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "## System Model\nComponents...",
                    "stage_02_output": "## Threats\nSpoofing threat...",
                }
            )
        )
        assert "## System Model" in result
        assert "Components..." in result
        assert "## Threats" in result
        assert "Spoofing threat..." in result

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

    def test_prior_stages_absent_when_no_output(self):
        result = build_prompt(StageContext())
        assert "PRIOR STAGE FINDINGS" not in result
        assert "<stage_01_system_model>" not in result
        assert "<stage_02_threat_identification>" not in result

    def test_prior_stage_01_absent_when_empty_string(self):
        result = build_prompt(StageContext(prior_outputs={"stage_01_output": ""}))
        assert "<stage_01_system_model>" not in result

    def test_prior_stage_02_absent_when_empty_string(self):
        result = build_prompt(StageContext(prior_outputs={"stage_02_output": ""}))
        assert "<stage_02_threat_identification>" not in result

    def test_only_stage_02_present(self):
        """Stage 2 output without Stage 1 should still inject correctly."""
        result = build_prompt(
            StageContext(prior_outputs={"stage_02_output": "Threats found"})
        )
        assert "<stage_02_threat_identification>" in result
        assert "<stage_01_system_model>" not in result

    def test_output_file_path(self):
        result = build_prompt(StageContext())
        assert "threatmodel/03-mitigations.md" in result

    def test_custom_output_dir(self):
        result = build_prompt(StageContext(), output_dir="output")
        assert "output/03-mitigations.md" in result

    def test_output_dir_trailing_slash_normalized(self):
        result = build_prompt(StageContext(), output_dir="output/")
        assert "output/03-mitigations.md" in result
        assert "output//03-mitigations.md" not in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(StageContext())
        assert "{prior_stages_section}" not in result
        assert "{output_dir}" not in result

    def test_contains_four_question_framework_context(self):
        result = build_prompt(StageContext())
        assert "What are we going to do about it?" in result

    def test_covers_countermeasure_identification(self):
        result = build_prompt(StageContext())
        assert "Countermeasure" in result or "countermeasure" in result

    def test_covers_existing_controls_assessment(self):
        result = build_prompt(StageContext())
        assert "Existing Controls" in result or "existing controls" in result

    def test_covers_gap_analysis(self):
        result = build_prompt(StageContext())
        assert "Gap Analysis" in result or "gap analysis" in result

    def test_covers_effort_estimates(self):
        result = build_prompt(StageContext())
        assert "Effort" in result or "effort" in result

    def test_covers_residual_risk(self):
        result = build_prompt(StageContext())
        assert "Residual" in result or "residual" in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholders(self):
        assert "{prior_stages_section}" in STAGE_PROMPT
        assert "{output_dir}" in STAGE_PROMPT
