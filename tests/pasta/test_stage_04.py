"""Tests for Stage 4 — Threat Analysis prompt template."""

from threatsmith.frameworks.pasta.stage_04_threat_analysis import (
    STAGE_PROMPT,
    build_prompt,
)
from threatsmith.frameworks.references.owasp import (
    OWASP_API_TOP_10,
    OWASP_LLM_TOP_10,
    OWASP_MOBILE_TOP_10,
    OWASP_WEB_TOP_10,
)
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

    def test_with_stage_02_output(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_02_output": "Technology stack and dependency analysis."
                }
            )
        )
        assert "Technology stack and dependency analysis." in result

    def test_with_stage_03_output(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_03_output": "Application decomposition and entry points."
                }
            )
        )
        assert "Application decomposition and entry points." in result

    def test_with_all_prior_stages(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "Stage 1 content",
                    "stage_02_output": "Stage 2 content",
                    "stage_03_output": "Stage 3 content",
                }
            )
        )
        assert "Stage 1 content" in result
        assert "Stage 2 content" in result
        assert "Stage 3 content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "S1 findings",
                    "stage_02_output": "S2 findings",
                    "stage_03_output": "S3 findings",
                }
            )
        )
        assert "<prior_stages>" in result
        assert "<stage_01_objectives>" in result
        assert "</stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" in result
        assert "</stage_02_technical_scope>" in result
        assert "<stage_03_decomposition>" in result
        assert "</stage_03_decomposition>" in result
        assert "</prior_stages>" in result

    def test_empty_context_omits_prior_stages(self):
        result = build_prompt(StageContext())
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_none_values_treated_as_absent(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": None,
                    "stage_02_output": None,
                    "stage_03_output": None,
                }
            )
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_empty_strings_treated_as_absent(self):
        result = build_prompt(
            StageContext(
                prior_outputs={
                    "stage_01_output": "",
                    "stage_02_output": "",
                    "stage_03_output": "",
                }
            )
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_output_file(self):
        result = build_prompt(StageContext())
        assert "threatmodel/04-threat-analysis.md" in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(StageContext())
        assert "{prior_stages_section}" not in result
        assert "{owasp_section}" not in result

    def test_prior_stages_includes_instructional_context(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "Some findings"})
        )
        assert "PRIOR STAGE FINDINGS" in result

    def test_partial_prior_stages_only_stage_01(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "S1 only"})
        )
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result

    def test_partial_prior_stages_only_stage_03(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_03_output": "S3 only"})
        )
        assert "<stage_01_objectives>" not in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" in result

    # --- OWASP reference injection tests (via context.references) ---

    def test_owasp_web_included_via_references(self):
        result = build_prompt(StageContext(references=[OWASP_WEB_TOP_10]))
        assert "A01:" in result
        assert "Broken Access Control" in result

    def test_owasp_section_header_when_references_present(self):
        result = build_prompt(StageContext(references=[OWASP_WEB_TOP_10]))
        assert "OWASP COVERAGE CHECKLISTS" in result

    def test_owasp_api_included_via_references(self):
        result = build_prompt(
            StageContext(references=[OWASP_WEB_TOP_10, OWASP_API_TOP_10])
        )
        assert "API1:" in result
        assert "Broken Object Level Authorization" in result

    def test_owasp_llm_included_via_references(self):
        result = build_prompt(
            StageContext(references=[OWASP_WEB_TOP_10, OWASP_LLM_TOP_10])
        )
        assert "LLM01:" in result
        assert "Prompt Injection" in result

    def test_owasp_mobile_included_via_references(self):
        result = build_prompt(
            StageContext(references=[OWASP_WEB_TOP_10, OWASP_MOBILE_TOP_10])
        )
        assert "M1:" in result
        assert "Improper Credential Usage" in result

    def test_all_owasp_variants_included_via_references(self):
        result = build_prompt(
            StageContext(
                references=[
                    OWASP_WEB_TOP_10,
                    OWASP_API_TOP_10,
                    OWASP_LLM_TOP_10,
                    OWASP_MOBILE_TOP_10,
                ]
            )
        )
        assert "A01:" in result
        assert "API1:" in result
        assert "LLM01:" in result
        assert "M1:" in result

    def test_no_owasp_section_when_no_references(self):
        result = build_prompt(StageContext())
        assert "OWASP COVERAGE CHECKLISTS" not in result

    def test_no_owasp_section_when_empty_references(self):
        result = build_prompt(StageContext(references=[]))
        assert "OWASP COVERAGE CHECKLISTS" not in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholders(self):
        assert "{prior_stages_section}" in STAGE_PROMPT
        assert "{owasp_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "{output_dir}04-threat-analysis.md" in STAGE_PROMPT

    def test_contains_stride_framework(self):
        assert "Spoofing" in STAGE_PROMPT
        assert "Tampering" in STAGE_PROMPT
        assert "Repudiation" in STAGE_PROMPT
        assert "Information Disclosure" in STAGE_PROMPT
        assert "Denial of Service" in STAGE_PROMPT
        assert "Elevation of Privilege" in STAGE_PROMPT

    def test_contains_probabilistic_analysis(self):
        assert "Probabilistic Attack Scenario" in STAGE_PROMPT

    def test_contains_regression_analysis(self):
        assert "Regression Analysis" in STAGE_PROMPT

    def test_contains_threat_intelligence(self):
        assert "Threat Intelligence Correlation" in STAGE_PROMPT

    def test_requires_complete_coverage(self):
        assert "Partial analysis" in STAGE_PROMPT
        assert "unacceptable" in STAGE_PROMPT
