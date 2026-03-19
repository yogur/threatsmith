"""Tests for the prompt assembler."""

from threatsmith.assembler import assemble_prompt
from threatsmith.frameworks.pasta import build_pasta_pack
from threatsmith.frameworks.references.owasp import OWASP_WEB_TOP_10
from threatsmith.frameworks.types import FrameworkPack, StageContext, StageSpec


def _pasta_pack():
    return build_pasta_pack()


def _stage(pack, number):
    """Return the StageSpec with the given number from a pack."""
    all_stages = list(pack.stages) + [pack.report_stage]
    for s in all_stages:
        if s.number == number:
            return s
    raise ValueError(f"No stage {number} in pack")


class TestTemplateSelection:
    """assemble_prompt selects the correct stage template for each stage number."""

    def test_stage_1_matches_direct_build(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = assemble_prompt(stage, pack)
        direct = stage.build_prompt(StageContext())
        assert result == direct

    def test_stage_2_matches_direct_build(self):
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = assemble_prompt(stage, pack)
        direct = stage.build_prompt(StageContext())
        assert result == direct

    def test_stage_4_matches_direct_build_with_references(self):
        """Stage 4 gets references resolved by the assembler."""
        pack = _pasta_pack()
        stage = _stage(pack, 4)
        result = assemble_prompt(stage, pack)
        # OWASP Web is always included for PASTA stage 4
        assert "A01:" in result
        assert "Broken Access Control" in result

    def test_all_stages_return_nonempty_strings(self):
        pack = _pasta_pack()
        for stage in list(pack.stages) + [pack.report_stage]:
            result = assemble_prompt(stage, pack)
            assert isinstance(result, str)
            assert len(result) > 0


class TestPriorOutputsInjection:
    """Prior stage outputs are formatted using XML-delimited tags."""

    def test_stage_2_prior_output_xml_wrapped(self):
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = assemble_prompt(
            stage, pack, prior_outputs={"stage_01_output": "Objectives"}
        )
        assert "<prior_stages>" in result
        assert "<stage_01_objectives>" in result
        assert "Objectives" in result
        assert "</stage_01_objectives>" in result
        assert "</prior_stages>" in result

    def test_stage_3_two_prior_outputs_xml_wrapped(self):
        pack = _pasta_pack()
        stage = _stage(pack, 3)
        result = assemble_prompt(
            stage,
            pack,
            prior_outputs={
                "stage_01_output": "Stage1 content",
                "stage_02_output": "Stage2 content",
            },
        )
        assert "<stage_01_objectives>" in result
        assert "Stage1 content" in result
        assert "<stage_02_technical_scope>" in result
        assert "Stage2 content" in result

    def test_stage_8_seven_prior_outputs(self):
        pack = _pasta_pack()
        stage = _stage(pack, 8)
        result = assemble_prompt(
            stage,
            pack,
            prior_outputs={f"stage_0{i}_output": f"S{i}" for i in range(1, 8)},
        )
        assert "<prior_stages>" in result
        assert "S7" in result

    def test_empty_prior_outputs_omits_xml(self):
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = assemble_prompt(stage, pack, prior_outputs={})
        assert "<prior_stages>" not in result

    def test_none_prior_outputs_omits_xml(self):
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = assemble_prompt(stage, pack, prior_outputs=None)
        assert "<prior_stages>" not in result

    def test_empty_string_prior_output_treated_as_absent(self):
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = assemble_prompt(stage, pack, prior_outputs={"stage_01_output": ""})
        assert "<prior_stages>" not in result


class TestReferenceInjection:
    """Reference conditions are evaluated and injected for reference-eligible stages."""

    def test_stage_4_owasp_web_always_included(self):
        pack = _pasta_pack()
        stage = _stage(pack, 4)
        result = assemble_prompt(stage, pack)
        assert "A01:" in result
        assert "OWASP COVERAGE CHECKLISTS" in result

    def test_stage_4_owasp_api_included_when_api_keyword_in_prior_outputs(self):
        pack = _pasta_pack()
        stage = _stage(pack, 4)
        result = assemble_prompt(
            stage,
            pack,
            prior_outputs={"stage_02_output": "The application exposes a REST API."},
        )
        assert "API1:" in result

    def test_stage_4_owasp_llm_included_when_llm_keyword_in_prior_outputs(self):
        pack = _pasta_pack()
        stage = _stage(pack, 4)
        result = assemble_prompt(
            stage,
            pack,
            prior_outputs={"stage_02_output": "Uses LangChain for LLM orchestration."},
        )
        assert "LLM01:" in result

    def test_stage_4_owasp_api_excluded_when_no_api_keywords(self):
        pack = _pasta_pack()
        stage = _stage(pack, 4)
        result = assemble_prompt(
            stage,
            pack,
            prior_outputs={"stage_02_output": "A simple Flask web application."},
        )
        assert "API1:" not in result

    def test_no_references_for_non_reference_stages(self):
        """Stages without reference_sets get no OWASP section."""
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = assemble_prompt(stage, pack)
        assert "OWASP COVERAGE CHECKLISTS" not in result


class TestScannerInfo:
    """scanner_info is forwarded to scanner-eligible stages."""

    def test_stage_5_scanner_snippets_injected(self):
        pack = _pasta_pack()
        stage = _stage(pack, 5)
        result = assemble_prompt(
            stage,
            pack,
            scanner_info={"available": ["semgrep"], "unavailable": []},
        )
        assert "semgrep" in result.lower()

    def test_stage_5_no_scanner_info_no_scanner_section(self):
        pack = _pasta_pack()
        stage = _stage(pack, 5)
        result = assemble_prompt(stage, pack, scanner_info=None)
        assert "## SCANNER INSTRUCTIONS" not in result

    def test_scanner_info_ignored_for_non_scanner_stages(self):
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = assemble_prompt(
            stage,
            pack,
            scanner_info={"available": ["semgrep"], "unavailable": []},
        )
        assert isinstance(result, str)


class TestUserObjectives:
    """user_objectives dict is forwarded to stages."""

    def test_stage_1_business_objectives_injected(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = assemble_prompt(
            stage,
            pack,
            user_objectives={"business_objectives": "We provide payments"},
        )
        assert "We provide payments" in result

    def test_stage_1_security_objectives_injected(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = assemble_prompt(
            stage,
            pack,
            user_objectives={"security_objectives": "PCI-DSS compliance required"},
        )
        assert "PCI-DSS compliance required" in result


class TestOutputDir:
    """output_dir is forwarded to each stage's build_prompt."""

    def test_custom_output_dir_reflected_in_prompt(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = assemble_prompt(stage, pack, output_dir="custom_output")
        assert "custom_output/" in result

    def test_default_output_dir_is_threatmodel(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = assemble_prompt(stage, pack)
        assert "threatmodel/" in result


# ---------------------------------------------------------------------------
# Framework-agnostic assembly — non-PASTA pack
# ---------------------------------------------------------------------------


def _make_simple_stage(
    number: int, is_scanner_stage: bool = False, has_references: bool = False
) -> StageSpec:
    """Build a StageSpec whose build_prompt records what context it received."""

    def build_prompt(context: StageContext, output_dir: str = "threatmodel") -> str:
        scanners = ",".join(context.scanners_available or [])
        refs = "|".join(context.references)
        return f"stage={number} scanners={scanners} refs={refs} output_dir={output_dir}"

    return StageSpec(
        number=number,
        name=f"stage_{number:02d}",
        output_file=f"0{number}-output.md",
        build_prompt=build_prompt,
    )


def _make_custom_pack(scanner_stages: list[int], reference_sets: dict) -> FrameworkPack:
    analysis = [_make_simple_stage(1), _make_simple_stage(2)]
    report = _make_simple_stage(3)
    return FrameworkPack(
        name="custom",
        display_name="Custom",
        description="Custom test pack",
        stages=analysis,
        report_stage=report,
        scanner_stages=scanner_stages,
        reference_sets=reference_sets,
    )


class TestFrameworkAgnosticAssembly:
    """assemble_prompt works correctly with non-PASTA packs."""

    def test_scanner_eligible_stage_receives_scanners(self):
        pack = _make_custom_pack(scanner_stages=[2], reference_sets={})
        stage = pack.stages[1]  # stage number 2
        result = assemble_prompt(
            stage,
            pack,
            scanner_info={"available": ["semgrep"], "unavailable": []},
        )
        assert "semgrep" in result

    def test_non_scanner_stage_receives_no_scanners(self):
        pack = _make_custom_pack(scanner_stages=[2], reference_sets={})
        stage = pack.stages[0]  # stage number 1 — not in scanner_stages
        result = assemble_prompt(
            stage,
            pack,
            scanner_info={"available": ["semgrep"], "unavailable": []},
        )
        assert "scanners=" in result
        # scanners should be empty for non-scanner stage
        assert "scanners=semgrep" not in result

    def test_always_reference_resolved_for_custom_pack(self):
        ref_config = [{"condition": "always", "reference": OWASP_WEB_TOP_10}]
        pack = _make_custom_pack(scanner_stages=[], reference_sets={1: ref_config})
        stage = pack.stages[0]  # stage number 1
        result = assemble_prompt(stage, pack)
        assert "A01:" in result

    def test_api_detected_reference_included_when_keyword_present(self):
        from threatsmith.frameworks.references.owasp import OWASP_API_TOP_10

        ref_config = [{"condition": "api_detected", "reference": OWASP_API_TOP_10}]
        pack = _make_custom_pack(scanner_stages=[], reference_sets={1: ref_config})
        stage = pack.stages[0]
        result = assemble_prompt(
            stage,
            pack,
            prior_outputs={"stage_01_output": "The system has a REST API endpoint."},
        )
        assert "API1:" in result

    def test_llm_detected_reference_excluded_when_no_keyword(self):
        from threatsmith.frameworks.references.owasp import OWASP_LLM_TOP_10

        ref_config = [{"condition": "llm_detected", "reference": OWASP_LLM_TOP_10}]
        pack = _make_custom_pack(scanner_stages=[], reference_sets={1: ref_config})
        stage = pack.stages[0]
        result = assemble_prompt(
            stage,
            pack,
            prior_outputs={"stage_01_output": "A simple CRUD application."},
        )
        assert "LLM01:" not in result
