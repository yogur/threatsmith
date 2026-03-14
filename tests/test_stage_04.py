"""Tests for Stage 4 — Threat Analysis prompt template."""

from threatsmith.prompts.contexts import ThreatAnalysisContext
from threatsmith.prompts.stage_04_threat_analysis import STAGE_PROMPT, build_prompt


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(ThreatAnalysisContext())
        assert isinstance(result, str)

    def test_with_stage_01_output(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_01_output="Business objectives and data sensitivity findings."
            )
        )
        assert "Business objectives and data sensitivity findings." in result

    def test_with_stage_02_output(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Technology stack and dependency analysis."
            )
        )
        assert "Technology stack and dependency analysis." in result

    def test_with_stage_03_output(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_03_output="Application decomposition and entry points."
            )
        )
        assert "Application decomposition and entry points." in result

    def test_with_all_prior_stages(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_01_output="Stage 1 content",
                stage_02_output="Stage 2 content",
                stage_03_output="Stage 3 content",
            )
        )
        assert "Stage 1 content" in result
        assert "Stage 2 content" in result
        assert "Stage 3 content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_01_output="S1 findings",
                stage_02_output="S2 findings",
                stage_03_output="S3 findings",
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
        result = build_prompt(ThreatAnalysisContext())
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_none_values_treated_as_absent(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_01_output=None,
                stage_02_output=None,
                stage_03_output=None,
            )
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_empty_strings_treated_as_absent(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_01_output="", stage_02_output="", stage_03_output=""
            )
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_output_file(self):
        result = build_prompt(ThreatAnalysisContext())
        assert "threatmodel/04-threat-analysis.md" in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(ThreatAnalysisContext())
        assert "{prior_stages_section}" not in result
        assert "{owasp_section}" not in result

    def test_prior_stages_includes_instructional_context(self):
        result = build_prompt(ThreatAnalysisContext(stage_01_output="Some findings"))
        assert "PRIOR STAGE FINDINGS" in result

    def test_partial_prior_stages_only_stage_01(self):
        result = build_prompt(ThreatAnalysisContext(stage_01_output="S1 only"))
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result

    def test_partial_prior_stages_only_stage_03(self):
        result = build_prompt(ThreatAnalysisContext(stage_03_output="S3 only"))
        assert "<stage_01_objectives>" not in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" in result

    # --- OWASP injection tests ---

    def test_owasp_web_always_included(self):
        result = build_prompt(ThreatAnalysisContext())
        assert "A01:" in result
        assert "Broken Access Control" in result

    def test_owasp_web_included_without_stage_02(self):
        result = build_prompt(ThreatAnalysisContext(stage_01_output="Some objectives"))
        assert "A01:" in result
        assert "OWASP COVERAGE CHECKLISTS" in result

    def test_owasp_api_included_when_rest_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="The application exposes a REST API for data access."
            )
        )
        assert "API1:" in result
        assert "Broken Object Level Authorization" in result

    def test_owasp_api_included_when_graphql_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="GraphQL endpoint serves the frontend."
            )
        )
        assert "API1:" in result

    def test_owasp_api_included_when_grpc_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Services communicate via gRPC internally."
            )
        )
        assert "API1:" in result

    def test_owasp_api_included_when_api_gateway_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Traffic is routed through an API gateway."
            )
        )
        assert "API1:" in result

    def test_owasp_api_excluded_when_no_api_keywords(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="A simple Flask web application with HTML templates."
            )
        )
        assert "API1:" not in result

    def test_owasp_llm_included_when_langchain_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="The app uses LangChain for LLM orchestration."
            )
        )
        assert "LLM01:" in result
        assert "Prompt Injection" in result

    def test_owasp_llm_included_when_openai_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Integration with OpenAI for text generation."
            )
        )
        assert "LLM01:" in result

    def test_owasp_llm_included_when_vector_database_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="RAG system backed by a vector database for retrieval."
            )
        )
        assert "LLM01:" in result

    def test_owasp_llm_included_when_llm_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="The system uses an LLM for code analysis."
            )
        )
        assert "LLM01:" in result

    def test_owasp_llm_excluded_when_no_llm_keywords(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="A Django web app with PostgreSQL database."
            )
        )
        assert "LLM01:" not in result

    def test_owasp_api_and_llm_both_included_when_both_present(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="REST API with LangChain-powered LLM features and a vector database."
            )
        )
        assert "API1:" in result
        assert "LLM01:" in result

    def test_owasp_keyword_matching_is_case_insensitive(self):
        result = build_prompt(
            ThreatAnalysisContext(stage_02_output="The backend serves a REST endpoint.")
        )
        assert "API1:" in result

    def test_owasp_api_not_included_without_stage_02(self):
        """API Top 10 requires Stage 2 output to check for keywords."""
        result = build_prompt(
            ThreatAnalysisContext(stage_01_output="REST API objectives")
        )
        assert "API1:" not in result

    def test_owasp_llm_not_included_without_stage_02(self):
        """LLM Top 10 requires Stage 2 output to check for keywords."""
        result = build_prompt(
            ThreatAnalysisContext(stage_01_output="LLM-based system objectives")
        )
        assert "LLM01:" not in result

    # --- OWASP Mobile Top 10 tests ---

    def test_owasp_mobile_included_when_android_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="The Android app communicates with the backend."
            )
        )
        assert "M1:" in result
        assert "Improper Credential Usage" in result

    def test_owasp_mobile_included_when_ios_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Native iOS application built with SwiftUI."
            )
        )
        assert "M1:" in result

    def test_owasp_mobile_included_when_react_native_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Cross-platform app built with React Native."
            )
        )
        assert "M1:" in result

    def test_owasp_mobile_included_when_flutter_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Mobile client developed with Flutter and Dart."
            )
        )
        assert "M1:" in result

    def test_owasp_mobile_included_when_swift_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="The client is written in Swift for Apple platforms."
            )
        )
        assert "M1:" in result

    def test_owasp_mobile_included_when_kotlin_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="Android client written in Kotlin with Jetpack Compose."
            )
        )
        assert "M1:" in result

    def test_owasp_mobile_included_when_mobile_keyword(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="The system includes a mobile companion app."
            )
        )
        assert "M1:" in result

    def test_owasp_mobile_excluded_when_no_mobile_keywords(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="A server-side Django web application with PostgreSQL."
            )
        )
        assert "M1:" not in result

    def test_owasp_mobile_not_included_without_stage_02(self):
        """Mobile Top 10 requires Stage 2 output to check for keywords."""
        result = build_prompt(
            ThreatAnalysisContext(stage_01_output="Mobile app objectives")
        )
        assert "M1:" not in result

    def test_all_owasp_variants_included_when_all_keywords_present(self):
        result = build_prompt(
            ThreatAnalysisContext(
                stage_02_output="REST API backend with LLM features and a Flutter mobile client."
            )
        )
        assert "A01:" in result
        assert "API1:" in result
        assert "LLM01:" in result
        assert "M1:" in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholders(self):
        assert "{prior_stages_section}" in STAGE_PROMPT
        assert "{owasp_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "threatmodel/04-threat-analysis.md" in STAGE_PROMPT

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
