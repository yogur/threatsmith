"""Tests for Stage 6 — Attack Modeling prompt template."""

from threatsmith.prompts.stage_06_attack_modeling import STAGE_PROMPT, build_prompt


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

    def test_with_stage_05_output(self):
        result = build_prompt(
            {"stage_05_output": "Vulnerability findings with CVSS scores."}
        )
        assert "Vulnerability findings with CVSS scores." in result

    def test_with_all_prior_stages(self):
        result = build_prompt(
            {
                "stage_01_output": "Stage 1 content",
                "stage_02_output": "Stage 2 content",
                "stage_03_output": "Stage 3 content",
                "stage_04_output": "Stage 4 content",
                "stage_05_output": "Stage 5 content",
            }
        )
        assert "Stage 1 content" in result
        assert "Stage 2 content" in result
        assert "Stage 3 content" in result
        assert "Stage 4 content" in result
        assert "Stage 5 content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            {
                "stage_01_output": "S1 findings",
                "stage_02_output": "S2 findings",
                "stage_03_output": "S3 findings",
                "stage_04_output": "S4 findings",
                "stage_05_output": "S5 findings",
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
        assert "<stage_05_vulnerability>" in result
        assert "</stage_05_vulnerability>" in result
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
                "stage_05_output": None,
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
                "stage_05_output": "",
            }
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_output_file(self):
        result = build_prompt({})
        assert "threatmodel/06-attack-modeling.md" in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt({})
        assert "{prior_stages_section}" not in result

    def test_prior_stages_includes_instructional_context(self):
        result = build_prompt({"stage_01_output": "Some findings"})
        assert "PRIOR STAGE FINDINGS" in result

    def test_partial_prior_stages_only_stage_01(self):
        result = build_prompt({"stage_01_output": "S1 only"})
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" not in result
        assert "<stage_05_vulnerability>" not in result

    def test_partial_prior_stages_only_stage_05(self):
        result = build_prompt({"stage_05_output": "S5 only"})
        assert "<stage_01_objectives>" not in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" not in result
        assert "<stage_05_vulnerability>" in result

    def test_partial_prior_stages_missing_middle(self):
        result = build_prompt({"stage_01_output": "S1", "stage_05_output": "S5"})
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" not in result
        assert "<stage_05_vulnerability>" in result

    def test_partial_stages_04_and_05_only(self):
        result = build_prompt(
            {"stage_04_output": "S4 threats", "stage_05_output": "S5 vulns"}
        )
        assert "<stage_01_objectives>" not in result
        assert "<stage_04_threat_analysis>" in result
        assert "<stage_05_vulnerability>" in result

    def test_prior_stages_context_mentions_stage_5_role(self):
        """Instructional context should tell the agent how to use Stage 5 output."""
        result = build_prompt({"stage_05_output": "Vulnerability findings"})
        assert "vulnerability" in result.lower()
        assert "building blocks" in result.lower()


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholder(self):
        assert "{prior_stages_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "threatmodel/06-attack-modeling.md" in STAGE_PROMPT

    def test_contains_attack_surface_analysis(self):
        assert "Attack Surface Analysis" in STAGE_PROMPT
        assert "pre-remediation" in STAGE_PROMPT.lower()
        assert "post-remediation" in STAGE_PROMPT.lower()

    def test_contains_attack_tree_development(self):
        assert "Attack Tree Development" in STAGE_PROMPT
        assert "flowchart TD" in STAGE_PROMPT
        assert "Mermaid" in STAGE_PROMPT

    def test_contains_mitre_attack_mapping(self):
        assert "MITRE ATT&CK" in STAGE_PROMPT
        assert "TA0001" in STAGE_PROMPT
        assert "T1190" in STAGE_PROMPT

    def test_contains_attack_vulnerability_exploit_analysis(self):
        assert "Attack-Vulnerability-Exploit Analysis" in STAGE_PROMPT
        assert "vulnerability chaining" in STAGE_PROMPT.lower()

    def test_contains_impact_summary(self):
        assert "Impact Summary and Risk Narrative" in STAGE_PROMPT
        assert "confidentiality" in STAGE_PROMPT.lower()
        assert "integrity" in STAGE_PROMPT.lower()
        assert "availability" in STAGE_PROMPT.lower()

    def test_contains_feasibility_assessment(self):
        assert "feasibility" in STAGE_PROMPT.lower()
        assert "Skill level" in STAGE_PROMPT

    def test_requires_complete_coverage(self):
        assert "ALL significant threats" in STAGE_PROMPT
        assert "Every confirmed vulnerability" in STAGE_PROMPT

    def test_contains_mermaid_pitfall_guidance(self):
        """Mermaid parentheses pitfall should be documented."""
        assert "parentheses" in STAGE_PROMPT.lower()

    def test_no_scanner_placeholder(self):
        """Stage 6 does not use scanner injection."""
        assert "{scanner_section}" not in STAGE_PROMPT
        assert "{owasp_section}" not in STAGE_PROMPT
