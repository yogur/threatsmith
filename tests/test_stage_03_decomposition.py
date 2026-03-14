"""Tests for Stage 3 — Application Decomposition prompt template."""

from threatsmith.prompts.contexts import DecompositionContext
from threatsmith.prompts.stage_03_decomposition import STAGE_PROMPT, build_prompt


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(DecompositionContext())
        assert isinstance(result, str)

    def test_with_stage_01_output(self):
        result = build_prompt(
            DecompositionContext(
                stage_01_output="Business objectives and data sensitivity findings."
            )
        )
        assert "Business objectives and data sensitivity findings." in result

    def test_with_stage_02_output(self):
        result = build_prompt(
            DecompositionContext(
                stage_02_output="Technology stack and dependency analysis."
            )
        )
        assert "Technology stack and dependency analysis." in result

    def test_with_both_prior_stages(self):
        result = build_prompt(
            DecompositionContext(
                stage_01_output="Stage 1 content",
                stage_02_output="Stage 2 content",
            )
        )
        assert "Stage 1 content" in result
        assert "Stage 2 content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            DecompositionContext(
                stage_01_output="S1 findings",
                stage_02_output="S2 findings",
            )
        )
        assert "<prior_stages>" in result
        assert "<stage_01_objectives>" in result
        assert "</stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" in result
        assert "</stage_02_technical_scope>" in result
        assert "</prior_stages>" in result

    def test_empty_context_omits_prior_stages(self):
        result = build_prompt(DecompositionContext())
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_none_values_treated_as_absent(self):
        result = build_prompt(
            DecompositionContext(stage_01_output=None, stage_02_output=None)
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_empty_strings_treated_as_absent(self):
        result = build_prompt(
            DecompositionContext(stage_01_output="", stage_02_output="")
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_output_file(self):
        result = build_prompt(DecompositionContext())
        assert "threatmodel/03-application-decomposition.md" in result

    def test_no_raw_placeholder_in_output(self):
        result = build_prompt(DecompositionContext())
        assert "{prior_stages_section}" not in result

    def test_prior_stages_includes_instructional_context(self):
        result = build_prompt(DecompositionContext(stage_01_output="Some findings"))
        assert "PRIOR STAGE FINDINGS" in result
        assert "data classifications" in result

    def test_partial_prior_stages_only_stage_01(self):
        result = build_prompt(DecompositionContext(stage_01_output="S1 only"))
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result

    def test_partial_prior_stages_only_stage_02(self):
        result = build_prompt(DecompositionContext(stage_02_output="S2 only"))
        assert "<stage_01_objectives>" not in result
        assert "<stage_02_technical_scope>" in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholder(self):
        assert "{prior_stages_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "{output_dir}03-application-decomposition.md" in STAGE_PROMPT

    def test_contains_mermaid_guidance(self):
        assert "mermaid" in STAGE_PROMPT.lower()
        assert "trust boundar" in STAGE_PROMPT.lower()
