"""Tests for the stage instruction assembler."""

from threatsmith.assembler import compose_stage_instruction
from threatsmith.frameworks.pasta import build_pasta_pack
from threatsmith.frameworks.stride_4q import build_stride_4q_pack
from threatsmith.frameworks.types import FrameworkPack, StageSpec


def _pasta_pack():
    return build_pasta_pack()


def _stride_pack():
    return build_stride_4q_pack()


def _stage(pack, number):
    """Return the StageSpec with the given number from a pack."""
    all_stages = list(pack.stages) + [pack.report_stage]
    for s in all_stages:
        if s.number == number:
            return s
    raise ValueError(f"No stage {number} in pack")


# ---------------------------------------------------------------------------
# Basic output contract
# ---------------------------------------------------------------------------


class TestBasicInstruction:
    """compose_stage_instruction returns a non-empty string for every stage."""

    def test_returns_string(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert isinstance(result, str)

    def test_returns_nonempty_string(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert len(result) > 0

    def test_all_pasta_stages_produce_instructions(self):
        pack = _pasta_pack()
        for stage in list(pack.stages) + [pack.report_stage]:
            result = compose_stage_instruction(stage, pack)
            assert isinstance(result, str) and len(result) > 0

    def test_all_stride_stages_produce_instructions(self):
        pack = _stride_pack()
        for stage in list(pack.stages) + [pack.report_stage]:
            result = compose_stage_instruction(stage, pack)
            assert isinstance(result, str) and len(result) > 0


# ---------------------------------------------------------------------------
# Skill name
# ---------------------------------------------------------------------------


class TestSkillName:
    """Instruction includes the pack's skill_name."""

    def test_pasta_skill_name_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "threatsmith-pasta" in result

    def test_stride_skill_name_in_instruction(self):
        pack = _stride_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "threatsmith-stride-4q" in result

    def test_custom_skill_name_in_instruction(self):
        pack = _pasta_pack()
        pack.skill_name = "my-custom-skill"
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "my-custom-skill" in result


# ---------------------------------------------------------------------------
# Stage identity
# ---------------------------------------------------------------------------


class TestStageIdentity:
    """Instruction includes the stage number and name."""

    def test_stage_number_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "01" in result

    def test_stage_name_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert stage.name in result

    def test_stage_4_number_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 4)
        result = compose_stage_instruction(stage, pack)
        assert "04" in result

    def test_report_stage_name_in_instruction(self):
        pack = _stride_pack()
        stage = _stage(pack, 5)
        result = compose_stage_instruction(stage, pack)
        assert stage.name in result


# ---------------------------------------------------------------------------
# Mode
# ---------------------------------------------------------------------------


class TestMode:
    """Instruction includes the specified mode."""

    def test_default_mode_is_from_code(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "from-code" in result

    def test_explicit_from_code_mode(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack, mode="from-code")
        assert "from-code" in result

    def test_from_docs_mode(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack, mode="from-docs")
        assert "from-docs" in result

    def test_pair_mode(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack, mode="pair")
        assert "pair" in result


# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------


class TestOutputDir:
    """Instruction includes the output directory."""

    def test_default_output_dir_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "threatmodel" in result

    def test_custom_output_dir_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack, output_dir="custom_output")
        assert "custom_output" in result

    def test_trailing_slash_stripped_from_output_dir(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack, output_dir="threatmodel/")
        # Should not double the slash
        assert "threatmodel//" not in result
        assert "threatmodel" in result


# ---------------------------------------------------------------------------
# Prior-stage file pointer
# ---------------------------------------------------------------------------


class TestFilePointer:
    """Prior stage outputs are referenced by file pointer, not inlined."""

    def test_output_dir_mentioned_as_prior_output_location(self):
        pack = _pasta_pack()
        stage = _stage(pack, 2)
        result = compose_stage_instruction(stage, pack, output_dir="threatmodel")
        assert "threatmodel" in result

    def test_no_xml_prior_stages_block(self):
        """No XML prior_stages injection — context is file-pointer only."""
        pack = _pasta_pack()
        stage = _stage(pack, 8)
        result = compose_stage_instruction(stage, pack)
        assert "<prior_stages>" not in result
        assert "</prior_stages>" not in result

    def test_no_inlined_stage_content(self):
        """Instruction does not inline prior stage text."""
        pack = _pasta_pack()
        stage = _stage(pack, 4)
        sentinel = "UNIQUE_PRIOR_CONTENT_XYZ"
        result = compose_stage_instruction(stage, pack)
        assert sentinel not in result


# ---------------------------------------------------------------------------
# Non-interactive signal
# ---------------------------------------------------------------------------


class TestNonInteractive:
    """Instruction signals non-interactive, single-stage execution."""

    def test_non_interactive_mentioned(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "non-interactive" in result

    def test_completion_without_pausing_mentioned(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack)
        assert "pausing" in result or "completion" in result


# ---------------------------------------------------------------------------
# User objectives
# ---------------------------------------------------------------------------


class TestUserObjectives:
    """User objectives are included in the instruction when provided."""

    def test_business_objectives_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(
            stage, pack, user_objectives={"business_objectives": "protect revenue"}
        )
        assert "protect revenue" in result

    def test_security_objectives_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(
            stage, pack, user_objectives={"security_objectives": "PCI-DSS compliance"}
        )
        assert "PCI-DSS compliance" in result

    def test_none_objectives_not_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack, user_objectives=None)
        assert "Business objectives:" not in result
        assert "Security objectives:" not in result

    def test_empty_objectives_not_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(stage, pack, user_objectives={})
        assert "Business objectives:" not in result

    def test_none_value_objectives_not_in_instruction(self):
        pack = _pasta_pack()
        stage = _stage(pack, 1)
        result = compose_stage_instruction(
            stage,
            pack,
            user_objectives={"business_objectives": None, "security_objectives": None},
        )
        assert "Business objectives:" not in result


# ---------------------------------------------------------------------------
# Framework-agnostic — custom pack
# ---------------------------------------------------------------------------


def _make_simple_pack(skill_name: str = "test-skill") -> FrameworkPack:
    stages = [
        StageSpec(number=1, name="Alpha", output_file="01-alpha.md"),
        StageSpec(number=2, name="Beta", output_file="02-beta.md"),
    ]
    report = StageSpec(number=3, name="Report", output_file="03-report.md")
    return FrameworkPack(
        name="test",
        display_name="Test",
        description="Test pack",
        stages=stages,
        report_stage=report,
        skill_name=skill_name,
    )


class TestCustomPack:
    def test_custom_pack_skill_name(self):
        pack = _make_simple_pack("custom-skill-name")
        stage = pack.stages[0]
        result = compose_stage_instruction(stage, pack)
        assert "custom-skill-name" in result

    def test_custom_pack_stage_name(self):
        pack = _make_simple_pack()
        stage = pack.stages[0]
        result = compose_stage_instruction(stage, pack)
        assert "Alpha" in result

    def test_custom_pack_report_stage(self):
        pack = _make_simple_pack()
        result = compose_stage_instruction(pack.report_stage, pack)
        assert "Report" in result
        assert "03" in result
