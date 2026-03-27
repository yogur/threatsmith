"""Tests for Stage 8 — Report Consolidation prompt template."""

from threatsmith.frameworks.pasta.stage_08_report import STAGE_PROMPT, build_prompt
from threatsmith.frameworks.types import StageContext


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(StageContext())
        assert isinstance(result, str)

    def test_with_stage_01_output(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "Business objectives and data sensitivity findings."
                }
            )
        )
        assert "Business objectives and data sensitivity findings." in result

    def test_with_stage_07_output(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_07_output": "Risk ratings and remediation roadmap."
                }
            )
        )
        assert "Risk ratings and remediation roadmap." in result

    def test_with_all_prior_stages(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "Stage 1 content",
                    "stage_02_output": "Stage 2 content",
                    "stage_03_output": "Stage 3 content",
                    "stage_04_output": "Stage 4 content",
                    "stage_05_output": "Stage 5 content",
                    "stage_06_output": "Stage 6 content",
                    "stage_07_output": "Stage 7 content",
                }
            )
        )
        assert "Stage 1 content" in result
        assert "Stage 2 content" in result
        assert "Stage 3 content" in result
        assert "Stage 4 content" in result
        assert "Stage 5 content" in result
        assert "Stage 6 content" in result
        assert "Stage 7 content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "S1 findings",
                    "stage_02_output": "S2 findings",
                    "stage_03_output": "S3 findings",
                    "stage_04_output": "S4 findings",
                    "stage_05_output": "S5 findings",
                    "stage_06_output": "S6 findings",
                    "stage_07_output": "S7 findings",
                }
            )
        )
        assert "<prior_stages>" in result
        assert "<stage_01_objectives>" in result
        assert "<stage_07_risk_impact>" in result
        assert "</prior_stages>" in result

    def test_empty_context_omits_prior_stages(self):
        result = build_prompt(StageContext())
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE OUTPUTS" not in result

    def test_references_output_file(self):
        result = build_prompt(StageContext())
        assert "threatmodel/08-report.md" in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(StageContext())
        assert "{prior_stages_section}" not in result

    def test_instructional_context_mentions_no_new_analysis(self):
        """Instructional context should reinforce no-new-analysis constraint."""
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "Some findings"})
        )
        assert (
            "not add new analysis" in result.lower()
            or "no new analysis" in result.lower()
        )

    def test_instructional_context_mentions_consolidation(self):
        """Instructional context should describe the consolidation role."""
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "Some findings"})
        )
        assert "consolidat" in result.lower()


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholder(self):
        assert "{prior_stages_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "{output_dir}08-report.md" in STAGE_PROMPT

    def test_is_not_a_pasta_stage(self):
        assert "NOT a PASTA stage" in STAGE_PROMPT

    def test_no_new_analysis(self):
        assert (
            "no new analysis" in STAGE_PROMPT.lower()
            or "not perform any new analysis" in STAGE_PROMPT.lower()
        )

    def test_requires_executive_summary(self):
        assert "Executive Summary" in STAGE_PROMPT
        assert "scope" in STAGE_PROMPT.lower()
        assert "critical findings" in STAGE_PROMPT.lower()

    def test_requires_content_preservation(self):
        assert "Mermaid" in STAGE_PROMPT
        assert "CVSS" in STAGE_PROMPT
        assert "CWE" in STAGE_PROMPT

    def test_requires_conversational_artifact_removal(self):
        assert "conversational artifact" in STAGE_PROMPT.lower()

    def test_requires_all_seven_stages(self):
        assert "Stage 1" in STAGE_PROMPT
        assert "Stage 2" in STAGE_PROMPT
        assert "Stage 3" in STAGE_PROMPT
        assert "Stage 4" in STAGE_PROMPT
        assert "Stage 5" in STAGE_PROMPT
        assert "Stage 6" in STAGE_PROMPT
        assert "Stage 7" in STAGE_PROMPT

    def test_requires_heading_normalization(self):
        assert "heading" in STAGE_PROMPT.lower()

    def test_preserves_code_references(self):
        assert (
            "file path" in STAGE_PROMPT.lower()
            or "file references" in STAGE_PROMPT.lower()
        )

    def test_no_scanner_or_owasp_placeholder(self):
        """Stage 8 does not use scanner or OWASP injection."""
        assert "{scanner_section}" not in STAGE_PROMPT
        assert "{owasp_section}" not in STAGE_PROMPT

    def test_report_title(self):
        assert "Threat Model Report" in STAGE_PROMPT
