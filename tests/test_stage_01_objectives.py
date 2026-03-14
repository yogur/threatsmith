"""Tests for Stage 1 — Define Objectives prompt template."""

from threatsmith.prompts.contexts import ObjectivesContext
from threatsmith.prompts.stage_01_objectives import STAGE_PROMPT, build_prompt


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(ObjectivesContext())
        assert isinstance(result, str)

    def test_with_business_objectives(self):
        result = build_prompt(
            ObjectivesContext(business_objectives="Protect user data and meet GDPR")
        )
        assert "Protect user data and meet GDPR" in result

    def test_with_security_objectives(self):
        result = build_prompt(
            ObjectivesContext(security_objectives="Reduce data exfiltration risk")
        )
        assert "Reduce data exfiltration risk" in result

    def test_with_both_objectives(self):
        result = build_prompt(
            ObjectivesContext(
                business_objectives="Protect user data",
                security_objectives="Reduce exfiltration risk",
            )
        )
        assert "Protect user data" in result
        assert "Reduce exfiltration risk" in result

    def test_empty_context_omits_user_section(self):
        result = build_prompt(ObjectivesContext())
        assert "USER-SUPPLIED OBJECTIVES" not in result

    def test_none_values_treated_as_absent(self):
        result = build_prompt(
            ObjectivesContext(
                business_objectives=None,
                security_objectives=None,
            )
        )
        assert "USER-SUPPLIED OBJECTIVES" not in result
        assert "None" not in result

    def test_references_output_file(self):
        result = build_prompt(ObjectivesContext())
        assert "threatmodel/01-objectives.md" in result

    def test_no_raw_placeholder_in_output(self):
        result = build_prompt(ObjectivesContext())
        assert "{user_objectives_section}" not in result

    def test_empty_string_values_treated_as_absent(self):
        result = build_prompt(
            ObjectivesContext(
                business_objectives="",
                security_objectives="",
            )
        )
        assert "USER-SUPPLIED OBJECTIVES" not in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholder(self):
        assert "{user_objectives_section}" in STAGE_PROMPT
