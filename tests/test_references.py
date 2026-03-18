"""Tests for the references conditional injection utility."""

from threatsmith.prompts.references.conditions import evaluate_reference_conditions
from threatsmith.prompts.references.owasp import (
    OWASP_API_TOP_10,
    OWASP_LLM_TOP_10,
    OWASP_MOBILE_TOP_10,
    OWASP_WEB_TOP_10,
)

ALWAYS_CONFIG = [{"condition": "always", "reference": OWASP_WEB_TOP_10}]
API_CONFIG = [{"condition": "api_detected", "reference": OWASP_API_TOP_10}]
LLM_CONFIG = [{"condition": "llm_detected", "reference": OWASP_LLM_TOP_10}]


class TestEvaluateReferenceConditions:
    def test_always_condition_returns_reference(self):
        result = evaluate_reference_conditions(ALWAYS_CONFIG, {})
        assert result == [OWASP_WEB_TOP_10]

    def test_always_condition_with_empty_prior_outputs(self):
        result = evaluate_reference_conditions(ALWAYS_CONFIG, {"stage_01": ""})
        assert result == [OWASP_WEB_TOP_10]

    def test_api_detected_with_matching_text(self):
        result = evaluate_reference_conditions(
            API_CONFIG, {"stage_02": "The service exposes a REST endpoint."}
        )
        assert result == [OWASP_API_TOP_10]

    def test_api_detected_case_insensitive(self):
        result = evaluate_reference_conditions(
            API_CONFIG, {"stage_02": "Uses GraphQL for queries."}
        )
        assert result == [OWASP_API_TOP_10]

    def test_api_detected_with_non_matching_text(self):
        result = evaluate_reference_conditions(
            API_CONFIG, {"stage_02": "A simple batch data pipeline."}
        )
        assert result == []

    def test_llm_detected_with_matching_text(self):
        result = evaluate_reference_conditions(
            LLM_CONFIG, {"stage_02": "Uses OpenAI for completions."}
        )
        assert result == [OWASP_LLM_TOP_10]

    def test_llm_detected_case_insensitive(self):
        result = evaluate_reference_conditions(
            LLM_CONFIG, {"stage_02": "Backed by LangChain agents."}
        )
        assert result == [OWASP_LLM_TOP_10]

    def test_llm_detected_with_non_matching_text(self):
        result = evaluate_reference_conditions(
            LLM_CONFIG, {"stage_02": "A traditional relational database application."}
        )
        assert result == []

    def test_multiple_conditions_in_one_call(self):
        config = [
            {"condition": "always", "reference": OWASP_WEB_TOP_10},
            {"condition": "api_detected", "reference": OWASP_API_TOP_10},
            {"condition": "llm_detected", "reference": OWASP_LLM_TOP_10},
        ]
        prior = {"stage_02": "REST API backed by an OpenAI LLM embedding service."}
        result = evaluate_reference_conditions(config, prior)
        assert result == [OWASP_WEB_TOP_10, OWASP_API_TOP_10, OWASP_LLM_TOP_10]

    def test_multiple_conditions_partial_match(self):
        config = [
            {"condition": "always", "reference": OWASP_WEB_TOP_10},
            {"condition": "api_detected", "reference": OWASP_API_TOP_10},
            {"condition": "llm_detected", "reference": OWASP_LLM_TOP_10},
        ]
        prior = {"stage_02": "A traditional web application with no external APIs."}
        result = evaluate_reference_conditions(config, prior)
        assert result == [OWASP_WEB_TOP_10]

    def test_searches_across_all_prior_output_values(self):
        result = evaluate_reference_conditions(
            API_CONFIG,
            {
                "stage_01": "business context",
                "stage_02": "Uses gRPC for inter-service communication.",
            },
        )
        assert result == [OWASP_API_TOP_10]

    def test_mobile_detected_with_matching_text(self):
        result = evaluate_reference_conditions(
            [{"condition": "mobile_detected", "reference": OWASP_MOBILE_TOP_10}],
            {"stage_02": "An Android and iOS application."},
        )
        assert result == [OWASP_MOBILE_TOP_10]

    def test_mobile_detected_with_non_matching_text(self):
        result = evaluate_reference_conditions(
            [{"condition": "mobile_detected", "reference": OWASP_MOBILE_TOP_10}],
            {"stage_02": "A server-side web application."},
        )
        assert result == []

    def test_empty_config_returns_empty_list(self):
        result = evaluate_reference_conditions([], {"stage_02": "REST API"})
        assert result == []
