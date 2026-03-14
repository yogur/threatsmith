"""Tests for Stage 2 — Define Technical Scope prompt template."""

from threatsmith.prompts.contexts import TechnicalScopeContext
from threatsmith.prompts.stage_02_technical_scope import STAGE_PROMPT, build_prompt


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(TechnicalScopeContext())
        assert isinstance(result, str)

    def test_with_stage_01_output(self):
        result = build_prompt(
            TechnicalScopeContext(
                stage_01_output="Business objectives and data sensitivity findings."
            )
        )
        assert "Business objectives and data sensitivity findings." in result

    def test_stage_01_output_wrapped_in_xml(self):
        result = build_prompt(
            TechnicalScopeContext(stage_01_output="Stage 1 content here")
        )
        assert "<prior_stages>" in result
        assert "<stage_01_objectives>" in result
        assert "</stage_01_objectives>" in result
        assert "</prior_stages>" in result

    def test_empty_context_omits_prior_stages(self):
        result = build_prompt(TechnicalScopeContext())
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_none_value_treated_as_absent(self):
        result = build_prompt(TechnicalScopeContext(stage_01_output=None))
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_empty_string_treated_as_absent(self):
        result = build_prompt(TechnicalScopeContext(stage_01_output=""))
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_output_file(self):
        result = build_prompt(TechnicalScopeContext())
        assert "threatmodel/02-technical-scope.md" in result

    def test_no_raw_placeholder_in_output(self):
        result = build_prompt(TechnicalScopeContext())
        assert "{prior_stages_section}" not in result

    def test_prior_stages_includes_instructional_context(self):
        result = build_prompt(TechnicalScopeContext(stage_01_output="Some findings"))
        assert "PRIOR STAGE FINDINGS" in result
        assert "data sensitivity classifications" in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholder(self):
        assert "{prior_stages_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "{output_dir}02-technical-scope.md" in STAGE_PROMPT
