"""Tests for Stage 7 — Risk and Impact Analysis prompt template."""

from threatsmith.prompts.contexts import RiskImpactContext
from threatsmith.prompts.stage_07_risk_impact import STAGE_PROMPT, build_prompt


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(RiskImpactContext())
        assert isinstance(result, str)

    def test_with_stage_01_output(self):
        result = build_prompt(
            RiskImpactContext(
                stage_01_output="Business objectives and data sensitivity findings."
            )
        )
        assert "Business objectives and data sensitivity findings." in result

    def test_with_stage_02_output(self):
        result = build_prompt(
            RiskImpactContext(
                stage_02_output="Technology stack and dependency analysis."
            )
        )
        assert "Technology stack and dependency analysis." in result

    def test_with_stage_03_output(self):
        result = build_prompt(
            RiskImpactContext(
                stage_03_output="Application decomposition and entry points."
            )
        )
        assert "Application decomposition and entry points." in result

    def test_with_stage_04_output(self):
        result = build_prompt(
            RiskImpactContext(
                stage_04_output="Threat inventory with STRIDE and attack scenarios."
            )
        )
        assert "Threat inventory with STRIDE and attack scenarios." in result

    def test_with_stage_05_output(self):
        result = build_prompt(
            RiskImpactContext(
                stage_05_output="Vulnerability findings with CVSS scores."
            )
        )
        assert "Vulnerability findings with CVSS scores." in result

    def test_with_stage_06_output(self):
        result = build_prompt(
            RiskImpactContext(stage_06_output="Attack trees and exploitation paths.")
        )
        assert "Attack trees and exploitation paths." in result

    def test_with_all_prior_stages(self):
        result = build_prompt(
            RiskImpactContext(
                stage_01_output="Stage 1 content",
                stage_02_output="Stage 2 content",
                stage_03_output="Stage 3 content",
                stage_04_output="Stage 4 content",
                stage_05_output="Stage 5 content",
                stage_06_output="Stage 6 content",
            )
        )
        assert "Stage 1 content" in result
        assert "Stage 2 content" in result
        assert "Stage 3 content" in result
        assert "Stage 4 content" in result
        assert "Stage 5 content" in result
        assert "Stage 6 content" in result

    def test_stage_outputs_wrapped_in_xml(self):
        result = build_prompt(
            RiskImpactContext(
                stage_01_output="S1 findings",
                stage_02_output="S2 findings",
                stage_03_output="S3 findings",
                stage_04_output="S4 findings",
                stage_05_output="S5 findings",
                stage_06_output="S6 findings",
            )
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
        assert "<stage_06_attack_modeling>" in result
        assert "</stage_06_attack_modeling>" in result
        assert "</prior_stages>" in result

    def test_empty_context_omits_prior_stages(self):
        result = build_prompt(RiskImpactContext())
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_none_values_treated_as_absent(self):
        result = build_prompt(
            RiskImpactContext(
                stage_01_output=None,
                stage_02_output=None,
                stage_03_output=None,
                stage_04_output=None,
                stage_05_output=None,
                stage_06_output=None,
            )
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_empty_strings_treated_as_absent(self):
        result = build_prompt(
            RiskImpactContext(
                stage_01_output="",
                stage_02_output="",
                stage_03_output="",
                stage_04_output="",
                stage_05_output="",
                stage_06_output="",
            )
        )
        assert "<prior_stages>" not in result
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_output_file(self):
        result = build_prompt(RiskImpactContext())
        assert "threatmodel/07-risk-and-impact-analysis.md" in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(RiskImpactContext())
        assert "{prior_stages_section}" not in result

    def test_prior_stages_includes_instructional_context(self):
        result = build_prompt(RiskImpactContext(stage_01_output="Some findings"))
        assert "PRIOR STAGE FINDINGS" in result

    def test_partial_prior_stages_only_stage_01(self):
        result = build_prompt(RiskImpactContext(stage_01_output="S1 only"))
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" not in result
        assert "<stage_05_vulnerability>" not in result
        assert "<stage_06_attack_modeling>" not in result

    def test_partial_prior_stages_only_stage_06(self):
        result = build_prompt(RiskImpactContext(stage_06_output="S6 only"))
        assert "<stage_01_objectives>" not in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" not in result
        assert "<stage_05_vulnerability>" not in result
        assert "<stage_06_attack_modeling>" in result

    def test_partial_prior_stages_missing_middle(self):
        result = build_prompt(
            RiskImpactContext(stage_01_output="S1", stage_06_output="S6")
        )
        assert "<stage_01_objectives>" in result
        assert "<stage_02_technical_scope>" not in result
        assert "<stage_03_decomposition>" not in result
        assert "<stage_04_threat_analysis>" not in result
        assert "<stage_05_vulnerability>" not in result
        assert "<stage_06_attack_modeling>" in result

    def test_partial_stages_05_and_06_only(self):
        result = build_prompt(
            RiskImpactContext(stage_05_output="S5 vulns", stage_06_output="S6 attacks")
        )
        assert "<stage_01_objectives>" not in result
        assert "<stage_05_vulnerability>" in result
        assert "<stage_06_attack_modeling>" in result

    def test_prior_stages_context_mentions_stage_6_role(self):
        """Instructional context should tell the agent how to use Stage 6 output."""
        result = build_prompt(
            RiskImpactContext(stage_06_output="Attack modeling findings")
        )
        assert "attack trees" in result.lower()
        assert "feasibility" in result.lower()

    def test_prior_stages_context_mentions_countermeasure_requirement(self):
        """Instructional context should reference countermeasure coverage."""
        result = build_prompt(
            RiskImpactContext(stage_05_output="Vulnerability findings")
        )
        assert "countermeasure" in result.lower()


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholder(self):
        assert "{prior_stages_section}" in STAGE_PROMPT

    def test_references_output_file(self):
        assert "threatmodel/07-risk-and-impact-analysis.md" in STAGE_PROMPT

    def test_contains_business_impact_qualification(self):
        assert "Business Impact Qualification and Quantification" in STAGE_PROMPT
        assert "Critical" in STAGE_PROMPT
        assert "financial exposure" in STAGE_PROMPT.lower()

    def test_contains_countermeasure_identification(self):
        assert "Countermeasure Identification" in STAGE_PROMPT
        assert "preventive" in STAGE_PROMPT.lower()
        assert "detective" in STAGE_PROMPT.lower()
        assert "corrective" in STAGE_PROMPT.lower()
        assert "compensating" in STAGE_PROMPT.lower()

    def test_contains_residual_risk_assessment(self):
        assert "Residual Risk Assessment" in STAGE_PROMPT
        assert "residual vulnerability" in STAGE_PROMPT.lower()
        assert "risk acceptance" in STAGE_PROMPT.lower()

    def test_contains_cost_effectiveness_analysis(self):
        assert "Mitigation Effectiveness vs Cost Analysis" in STAGE_PROMPT
        assert "quick wins" in STAGE_PROMPT.lower()
        assert "diminishing returns" in STAGE_PROMPT.lower()

    def test_contains_residual_benefits(self):
        assert "residual benefits" in STAGE_PROMPT.lower()
        assert "cross-cutting" in STAGE_PROMPT.lower()

    def test_contains_remediation_roadmap(self):
        assert "Prioritized Remediation Roadmap" in STAGE_PROMPT
        assert "P0" in STAGE_PROMPT
        assert "P1" in STAGE_PROMPT
        assert "P2" in STAGE_PROMPT
        assert "P3" in STAGE_PROMPT

    def test_contains_likelihood_assessment(self):
        assert "likelihood" in STAGE_PROMPT.lower()
        assert "Almost Certain" in STAGE_PROMPT

    def test_contains_risk_matrix(self):
        assert "risk matrix" in STAGE_PROMPT.lower()
        assert "risk rating" in STAGE_PROMPT.lower()

    def test_requires_complete_coverage(self):
        assert "Every attack scenario" in STAGE_PROMPT
        assert "Every confirmed vulnerability" in STAGE_PROMPT

    def test_no_scanner_or_owasp_placeholder(self):
        """Stage 7 does not use scanner or OWASP injection."""
        assert "{scanner_section}" not in STAGE_PROMPT
        assert "{owasp_section}" not in STAGE_PROMPT
