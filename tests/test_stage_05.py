"""Tests for Stage 5 — Vulnerability and Weakness Analysis prompt template."""

from threatsmith.prompts.stage_05_vulnerability import STAGE_PROMPT, build_prompt


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt({})
        assert isinstance(result, str)

    def test_with_stage_01_output(self):
        result = build_prompt(
            {"stage_01_output": "Business objectives and data sensitivity findings."}
        )
        assert "Business objectives and data sensitivity findings." in result

    def test_with_stage_02_output(self):
        result = build_prompt(
            {"stage_02_output": "Technology stack and dependency analysis."}
        )
        assert "Technology stack and dependency analysis." in result

    def test_with_stage_03_output(self):
        result = build_prompt(
            {"stage_03_output": "Application decomposition and entry points."}
        )
        assert "Application decomposition and entry points." in result

    def test_with_stage_04_output(self):
        result = build_prompt(
            {"stage_04_output": "Threat inventory with STRIDE and attack scenarios."}
        )
        assert "Threat inventory with STRIDE and attack scenarios." in result

    def test_with_all_prior_stages(self):
        result = build_prompt(
            {
                "stage_01_output": "Stage 1 content",
                "stage_02_output": "Stage 2 content",
                "stage_03_output": "Stage 3 content",
                "stage_04_output": "Stage 4 content",
            }
        )
        assert "Stage 1 content" in result
        assert "Stage 2 content" in result
        assert "Stage 3 content" in result
        assert "Stage 4 content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            {
                "stage_01_output": "S1 findings",
                "stage_02_output": "S2 findings",
                "stage_03_output": "S3 findings",
                "stage_04_output": "S4 findings",
            }
        )
        assert "<prior_stages>" in result
        assert "<stage_01_objectives>" in result
        assert "</stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" in result
        assert "</stage_02_technical_scope>" in result
        assert "<stage_03_decomposition>" in result
        assert "</stage_03_decomposition>" in result
        assert "<stage_04_threat_analysis>" in result
        assert "</stage_04_threat_analysis>" in result
        assert "</prior_stages>" in result

    def test_empty_context_omits_prior_stages(self):
        result = build_prompt({})
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_none_values_treated_as_absent(self):
        result = build_prompt(
            {
                "stage_01_output": None,
                "stage_02_output": None,
                "stage_03_output": None,
                "stage_04_output": None,
            }
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_empty_strings_treated_as_absent(self):
        result = build_prompt(
            {
                "stage_01_output": "",
                "stage_02_output": "",
                "stage_03_output": "",
                "stage_04_output": "",
            }
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_output_file(self):
        result = build_prompt({})
        assert "threatmodel/05-vulnerability-analysis.md" in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt({})
        assert "{prior_stages_section}" not in result
        assert "{scanner_section}" not in result

    def test_prior_stages_includes_instructional_context(self):
        result = build_prompt({"stage_01_output": "Some findings"})
        assert "PRIOR STAGE FINDINGS" in result

    def test_partial_prior_stages_only_stage_01(self):
        result = build_prompt({"stage_01_output": "S1 only"})
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" not in result

    def test_partial_prior_stages_only_stage_04(self):
        result = build_prompt({"stage_04_output": "S4 only"})
        assert "<stage_01_objectives>" not in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" in result

    def test_partial_prior_stages_missing_middle(self):
        result = build_prompt({"stage_01_output": "S1", "stage_04_output": "S4"})
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" in result

    # --- Scanner snippet injection tests ---

    def test_semgrep_snippet_included_when_available(self):
        result = build_prompt({"scanners_available": ["semgrep"]})
        assert "Semgrep" in result
        assert "semgrep scan" in result

    def test_trivy_snippet_included_when_available(self):
        result = build_prompt({"scanners_available": ["trivy"]})
        assert "Trivy" in result
        assert "trivy fs" in result

    def test_gitleaks_snippet_included_when_available(self):
        result = build_prompt({"scanners_available": ["gitleaks"]})
        assert "Gitleaks" in result
        assert "gitleaks dir" in result

    def test_all_scanners_included_when_all_available(self):
        result = build_prompt({"scanners_available": ["semgrep", "trivy", "gitleaks"]})
        assert "semgrep scan" in result
        assert "trivy fs" in result
        assert "gitleaks dir" in result

    def test_scanner_section_header_when_scanners_available(self):
        result = build_prompt({"scanners_available": ["semgrep"]})
        assert "## SCANNER INSTRUCTIONS" in result

    def test_no_scanner_section_when_no_scanners(self):
        result = build_prompt({})
        assert "## SCANNER INSTRUCTIONS" not in result

    def test_no_scanner_section_when_empty_list(self):
        result = build_prompt({"scanners_available": []})
        assert "## SCANNER INSTRUCTIONS" not in result

    def test_no_scanner_section_when_none(self):
        result = build_prompt({"scanners_available": None})
        assert "## SCANNER INSTRUCTIONS" not in result

    def test_only_available_scanners_included(self):
        result = build_prompt({"scanners_available": ["trivy"]})
        assert "trivy fs" in result
        assert "semgrep scan" not in result
        assert "gitleaks dir" not in result

    def test_unknown_scanner_name_ignored(self):
        result = build_prompt({"scanners_available": ["unknown_scanner"]})
        assert "SCANNER INSTRUCTIONS" in result
        assert "unknown_scanner" not in result

    def test_mixed_known_and_unknown_scanners(self):
        result = build_prompt({"scanners_available": ["semgrep", "unknown_scanner"]})
        assert "semgrep scan" in result
        assert "unknown_scanner" not in result

    def test_scanner_and_prior_stages_combined(self):
        result = build_prompt(
            {
                "stage_04_output": "Stage 4 threats",
                "scanners_available": ["semgrep", "trivy"],
            }
        )
        assert "<stage_04_threat_analysis>" in result
        assert "SCANNER INSTRUCTIONS" in result
        assert "semgrep scan" in result
        assert "trivy fs" in result

    def test_scanner_snippet_includes_usage_example(self):
        """Scanner snippets should contain example commands users can run."""
        result = build_prompt({"scanners_available": ["semgrep", "trivy", "gitleaks"]})
        # Each snippet contains an example command
        assert "--config auto" in result  # semgrep
        assert "--format json" in result  # trivy
        assert "--report-format json" in result  # gitleaks


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholders(self):
        assert "{prior_stages_section}" in STAGE_PROMPT
        assert "{scanner_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "threatmodel/05-vulnerability-analysis.md" in STAGE_PROMPT

    def test_contains_cvss_scoring(self):
        assert "CVSS 3.1" in STAGE_PROMPT
        assert "Attack Vector" in STAGE_PROMPT
        assert "Attack Complexity" in STAGE_PROMPT

    def test_contains_cwe_classification(self):
        assert "CWE" in STAGE_PROMPT
        assert "Common Weakness Enumeration" in STAGE_PROMPT

    def test_contains_cve_cross_reference(self):
        assert "CVE" in STAGE_PROMPT

    def test_contains_threat_tree_methodology(self):
        assert "Threat-to-Vulnerability Mapping" in STAGE_PROMPT
        assert "threat tree" in STAGE_PROMPT.lower()

    def test_contains_design_flaw_analysis(self):
        assert "Design Flaw Analysis" in STAGE_PROMPT
        assert "abuse case" in STAGE_PROMPT.lower()
        assert "use case" in STAGE_PROMPT.lower()

    def test_contains_impact_assessment(self):
        assert "Impact and Exposure Assessment" in STAGE_PROMPT

    def test_contains_remediation_guidance(self):
        assert "Remediation" in STAGE_PROMPT
        assert "effort estimate" in STAGE_PROMPT.lower()

    def test_requires_completeness(self):
        assert "Every Stage 4 threat" in STAGE_PROMPT
        assert "no exploitable weakness" in STAGE_PROMPT
