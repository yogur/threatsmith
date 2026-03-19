"""Tests for 4QF+STRIDE Stage 5 — Report Consolidation prompt template."""

from threatsmith.frameworks.stride_4q.stage_05_report import STAGE_PROMPT, build_prompt
from threatsmith.frameworks.types import StageContext


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(StageContext())
        assert isinstance(result, str)

    def test_with_all_four_stage_outputs(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "Stage 1 system model content",
                    "stage_02_output": "Stage 2 threat identification content",
                    "stage_03_output": "Stage 3 mitigations content",
                    "stage_04_output": "Stage 4 validation content",
                }
            )
        )
        assert "Stage 1 system model content" in result
        assert "Stage 2 threat identification content" in result
        assert "Stage 3 mitigations content" in result
        assert "Stage 4 validation content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "S1 findings",
                    "stage_02_output": "S2 findings",
                    "stage_03_output": "S3 findings",
                    "stage_04_output": "S4 findings",
                }
            )
        )
        assert "<prior_stages>" in result
        assert "<stage_01_system_model>" in result
        assert "</stage_01_system_model>" in result
        assert "<stage_02_threat_identification>" in result
        assert "</stage_02_threat_identification>" in result
        assert "<stage_03_mitigations>" in result
        assert "</stage_03_mitigations>" in result
        assert "<stage_04_validation>" in result
        assert "</stage_04_validation>" in result
        assert "</prior_stages>" in result

    def test_with_stage_01_output_only(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "System model findings."})
        )
        assert "System model findings." in result
        assert "<stage_01_system_model>" in result
        assert "<stage_02_threat_identification>" not in result

    def test_with_stage_04_output_only(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_04_output": "Validation assessment."})
        )
        assert "Validation assessment." in result
        assert "<stage_04_validation>" in result
        assert "<stage_01_system_model>" not in result

    def test_empty_context_omits_prior_stages(self):
        result = build_prompt(StageContext())
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE OUTPUTS" not in result

    def test_empty_string_output_treated_as_absent(self):
        result = build_prompt(StageContext(prior_outputs={"stage_01_output": ""}))
        assert "<prior_stages>" not in result

    def test_references_output_file(self):
        result = build_prompt(StageContext())
        assert "threatmodel/05-report.md" in result

    def test_custom_output_dir(self):
        result = build_prompt(StageContext(), output_dir="custom_output")
        assert "custom_output/05-report.md" in result

    def test_trailing_slash_normalization(self):
        result = build_prompt(StageContext(), output_dir="custom_output/")
        assert "custom_output/05-report.md" in result
        assert "custom_output//05-report.md" not in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(StageContext())
        assert "{prior_stages_section}" not in result
        assert "{output_dir}" not in result

    def test_instructional_context_mentions_no_new_analysis(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "Some findings"})
        )
        assert (
            "not add new analysis" in result.lower()
            or "no new analysis" in result.lower()
            or "not perform any new analysis" in result.lower()
        )

    def test_instructional_context_mentions_consolidation(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "Some findings"})
        )
        assert "consolidat" in result.lower()

    def test_prior_stages_header_text(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "Some content"})
        )
        assert "PRIOR STAGE OUTPUTS" in result

    def test_stages_independently_optional(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_02_output": "Threats found",
                    "stage_04_output": "Validation done",
                }
            )
        )
        assert "<stage_02_threat_identification>" in result
        assert "<stage_04_validation>" in result
        assert "<stage_01_system_model>" not in result
        assert "<stage_03_mitigations>" not in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_prior_stages_placeholder(self):
        assert "{prior_stages_section}" in STAGE_PROMPT

    def test_contains_output_dir_placeholder(self):
        assert "{output_dir}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "05-report.md" in STAGE_PROMPT

    def test_no_new_analysis(self):
        assert (
            "no new analysis" in STAGE_PROMPT.lower()
            or "not perform any new analysis" in STAGE_PROMPT.lower()
        )

    def test_requires_executive_summary(self):
        assert "Executive Summary" in STAGE_PROMPT

    def test_requires_content_preservation(self):
        assert "Mermaid" in STAGE_PROMPT

    def test_requires_conversational_artifact_removal(self):
        assert "conversational artifact" in STAGE_PROMPT.lower()

    def test_requires_all_four_stages(self):
        assert "Stage 1" in STAGE_PROMPT
        assert "Stage 2" in STAGE_PROMPT
        assert "Stage 3" in STAGE_PROMPT
        assert "Stage 4" in STAGE_PROMPT

    def test_references_stride_stage_names(self):
        assert "System Model" in STAGE_PROMPT
        assert "Threat Identification" in STAGE_PROMPT
        assert "Mitigations" in STAGE_PROMPT
        assert "Validation" in STAGE_PROMPT

    def test_requires_heading_normalization(self):
        assert "heading" in STAGE_PROMPT.lower()

    def test_preserves_code_references(self):
        assert (
            "file path" in STAGE_PROMPT.lower()
            or "file references" in STAGE_PROMPT.lower()
        )

    def test_no_scanner_or_owasp_placeholder(self):
        assert "{scanner_section}" not in STAGE_PROMPT
        assert "{owasp_section}" not in STAGE_PROMPT
        assert "{references_section}" not in STAGE_PROMPT

    def test_report_title(self):
        assert "Threat Model Report" in STAGE_PROMPT

    def test_mentions_4qf_stride(self):
        assert "4QF" in STAGE_PROMPT or "Four Question Framework" in STAGE_PROMPT
        assert "STRIDE" in STAGE_PROMPT
