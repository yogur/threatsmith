"""Tests for the prompt assembler."""

import pytest

from threatsmith.prompts import (
    stage_01_objectives,
    stage_02_technical_scope,
    stage_03_decomposition,
    stage_04_threat_analysis,
    stage_05_vulnerability,
    stage_06_attack_modeling,
    stage_07_risk_impact,
    stage_08_report,
)
from threatsmith.prompts.assembler import assemble_prompt


class TestTemplateSelection:
    """assemble_prompt selects the correct stage template for each stage number."""

    def test_stage_1_contains_stage_1_content(self):
        result = assemble_prompt(1)
        # Stage 1 STAGE_PROMPT contains unique text from stage_01_objectives
        direct = stage_01_objectives.build_prompt(
            stage_01_objectives.ObjectivesContext()
        )
        assert result == direct

    def test_stage_2_matches_direct_build(self):
        result = assemble_prompt(2)
        direct = stage_02_technical_scope.build_prompt(
            stage_02_technical_scope.TechnicalScopeContext()
        )
        assert result == direct

    def test_stage_3_matches_direct_build(self):
        result = assemble_prompt(3)
        direct = stage_03_decomposition.build_prompt(
            stage_03_decomposition.DecompositionContext()
        )
        assert result == direct

    def test_stage_4_matches_direct_build(self):
        result = assemble_prompt(4)
        direct = stage_04_threat_analysis.build_prompt(
            stage_04_threat_analysis.ThreatAnalysisContext()
        )
        assert result == direct

    def test_stage_5_matches_direct_build(self):
        result = assemble_prompt(5)
        direct = stage_05_vulnerability.build_prompt(
            stage_05_vulnerability.VulnerabilityContext()
        )
        assert result == direct

    def test_stage_6_matches_direct_build(self):
        result = assemble_prompt(6)
        direct = stage_06_attack_modeling.build_prompt(
            stage_06_attack_modeling.AttackModelingContext()
        )
        assert result == direct

    def test_stage_7_matches_direct_build(self):
        result = assemble_prompt(7)
        direct = stage_07_risk_impact.build_prompt(
            stage_07_risk_impact.RiskImpactContext()
        )
        assert result == direct

    def test_stage_8_matches_direct_build(self):
        result = assemble_prompt(8)
        direct = stage_08_report.build_prompt(stage_08_report.ReportContext())
        assert result == direct

    def test_invalid_stage_raises_value_error(self):
        with pytest.raises(ValueError, match="stage_number must be between 1 and 8"):
            assemble_prompt(0)

    def test_stage_9_raises_value_error(self):
        with pytest.raises(ValueError, match="stage_number must be between 1 and 8"):
            assemble_prompt(9)


class TestPriorOutputsInjection:
    """Prior stage outputs are formatted using XML-delimited tags."""

    def test_stage_2_prior_output_xml_wrapped(self):
        result = assemble_prompt(2, prior_outputs={"stage_01_output": "Objectives"})
        assert "<prior_stages>" in result
        assert "<stage_01_objectives>" in result
        assert "Objectives" in result
        assert "</stage_01_objectives>" in result
        assert "</prior_stages>" in result

    def test_stage_3_two_prior_outputs_xml_wrapped(self):
        result = assemble_prompt(
            3,
            prior_outputs={
                "stage_01_output": "Stage1 content",
                "stage_02_output": "Stage2 content",
            },
        )
        assert "<stage_01_objectives>" in result
        assert "Stage1 content" in result
        assert "<stage_02_technical_scope>" in result
        assert "Stage2 content" in result

    def test_stage_4_three_prior_outputs(self):
        result = assemble_prompt(
            4,
            prior_outputs={
                "stage_01_output": "S1",
                "stage_02_output": "S2",
                "stage_03_output": "S3",
            },
        )
        assert "S1" in result
        assert "S2" in result
        assert "S3" in result
        assert "<prior_stages>" in result

    def test_stage_5_four_prior_outputs(self):
        result = assemble_prompt(
            5,
            prior_outputs={
                "stage_01_output": "S1",
                "stage_02_output": "S2",
                "stage_03_output": "S3",
                "stage_04_output": "S4",
            },
        )
        assert "<prior_stages>" in result
        assert "S4" in result

    def test_stage_6_five_prior_outputs(self):
        result = assemble_prompt(
            6,
            prior_outputs={f"stage_0{i}_output": f"S{i}" for i in range(1, 6)},
        )
        assert "<prior_stages>" in result
        assert "S5" in result

    def test_stage_7_six_prior_outputs(self):
        result = assemble_prompt(
            7,
            prior_outputs={f"stage_0{i}_output": f"S{i}" for i in range(1, 7)},
        )
        assert "<prior_stages>" in result
        assert "S6" in result

    def test_stage_8_seven_prior_outputs(self):
        result = assemble_prompt(
            8,
            prior_outputs={f"stage_0{i}_output": f"S{i}" for i in range(1, 8)},
        )
        assert "<prior_stages>" in result
        assert "S7" in result

    def test_empty_prior_outputs_omits_xml(self):
        result = assemble_prompt(2, prior_outputs={})
        assert "<prior_stages>" not in result

    def test_none_prior_outputs_omits_xml(self):
        result = assemble_prompt(2, prior_outputs=None)
        assert "<prior_stages>" not in result

    def test_empty_string_prior_output_treated_as_absent(self):
        result = assemble_prompt(2, prior_outputs={"stage_01_output": ""})
        assert "<prior_stages>" not in result


class TestScannerInfo:
    """scanner_info is forwarded to Stage 5 for scanner snippet injection."""

    def test_stage_5_scanner_snippets_injected(self):
        result = assemble_prompt(
            5,
            scanner_info={"available": ["semgrep"], "unavailable": []},
        )
        assert "semgrep" in result.lower()

    def test_stage_5_no_scanner_info_no_scanner_section(self):
        result = assemble_prompt(5, scanner_info=None)
        assert "## SCANNER INSTRUCTIONS" not in result

    def test_scanner_info_ignored_for_other_stages(self):
        # Stage 2 doesn't use scanner info — no error should occur
        result = assemble_prompt(
            2, scanner_info={"available": ["semgrep"], "unavailable": []}
        )
        assert isinstance(result, str)


class TestUserObjectives:
    """user_objectives dict is forwarded to Stage 1."""

    def test_stage_1_business_objectives_injected(self):
        result = assemble_prompt(
            1,
            user_objectives={"business_objectives": "We provide payments"},
        )
        assert "We provide payments" in result

    def test_stage_1_security_objectives_injected(self):
        result = assemble_prompt(
            1,
            user_objectives={"security_objectives": "PCI-DSS compliance required"},
        )
        assert "PCI-DSS compliance required" in result

    def test_user_objectives_ignored_for_other_stages(self):
        result = assemble_prompt(
            2,
            user_objectives={"business_objectives": "Should be ignored"},
        )
        assert isinstance(result, str)
        # Stage 2 template doesn't have a user objectives section
        assert "Should be ignored" not in result


class TestCommitHash:
    """commit_hash is accepted without error."""

    def test_commit_hash_accepted(self):
        result = assemble_prompt(1, commit_hash="abc123def456")
        assert isinstance(result, str)


class TestOutputDir:
    """output_dir is forwarded to each stage's build_prompt."""

    def test_custom_output_dir_reflected_in_prompt(self):
        result = assemble_prompt(1, output_dir="custom_output")
        assert "custom_output/" in result

    def test_default_output_dir_is_threatmodel(self):
        result = assemble_prompt(1)
        assert "threatmodel/" in result

    def test_output_dir_forwarded_for_stages_with_placeholder(self):
        # Stages 1-5 use {output_dir} placeholder; 6-8 have hardcoded path in template
        for stage in range(1, 6):
            result = assemble_prompt(stage, output_dir="mydir")
            assert "mydir/" in result, f"Stage {stage} did not contain 'mydir/'"


class TestReturnType:
    """assemble_prompt always returns a non-empty string."""

    def test_returns_string_for_all_stages(self):
        for stage in range(1, 9):
            result = assemble_prompt(stage)
            assert isinstance(result, str)
            assert len(result) > 0
