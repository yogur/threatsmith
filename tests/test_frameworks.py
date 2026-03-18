import pytest

from threatsmith.frameworks import (
    _REGISTRY,
    FrameworkPack,
    StageSpec,
    get_framework,
    list_frameworks,
    register_framework,
)


def _make_stage(number: int) -> StageSpec:
    return StageSpec(
        number=number,
        name=f"Stage {number}",
        output_file=f"0{number}-output.md",
        build_prompt=lambda ctx: f"prompt {number}",
    )


def _make_pack(name: str, display_name: str) -> FrameworkPack:
    stage = _make_stage(1)
    report = _make_stage(99)
    return FrameworkPack(
        name=name,
        display_name=display_name,
        description=f"{display_name} description",
        stages=[stage],
        report_stage=report,
        scanner_stages=[1],
        reference_sets={1: [{"condition": "always", "value": "ref"}]},
    )


@pytest.fixture(autouse=True)
def clean_registry():
    """Restore registry state after each test."""
    original = dict(_REGISTRY)
    yield
    _REGISTRY.clear()
    _REGISTRY.update(original)


class TestDataModelConstruction:
    def test_stage_spec_fields(self):
        def fn(ctx):
            return "prompt"

        stage = StageSpec(
            number=1,
            name="System Model",
            output_file="01-system-model.md",
            build_prompt=fn,
        )
        assert stage.number == 1
        assert stage.name == "System Model"
        assert stage.output_file == "01-system-model.md"
        assert stage.build_prompt is fn

    def test_framework_pack_fields(self):
        stage = _make_stage(1)
        report = _make_stage(5)
        pack = FrameworkPack(
            name="stride-4q",
            display_name="4QF + STRIDE",
            description="A lightweight framework",
            stages=[stage],
            report_stage=report,
            scanner_stages=[1],
            reference_sets={1: [{"condition": "always", "value": "STRIDE_CATEGORIES"}]},
        )
        assert pack.name == "stride-4q"
        assert pack.display_name == "4QF + STRIDE"
        assert pack.description == "A lightweight framework"
        assert pack.stages == [stage]
        assert pack.report_stage is report
        assert pack.scanner_stages == [1]
        assert pack.reference_sets == {
            1: [{"condition": "always", "value": "STRIDE_CATEGORIES"}]
        }

    def test_framework_pack_defaults(self):
        stage = _make_stage(1)
        pack = FrameworkPack(
            name="test",
            display_name="Test",
            description="desc",
            stages=[stage],
            report_stage=stage,
        )
        assert pack.scanner_stages == []
        assert pack.reference_sets == {}

    def test_stage_spec_build_prompt_callable(self):
        stage = _make_stage(2)
        result = stage.build_prompt({"key": "value"})
        assert result == "prompt 2"


class TestGetFramework:
    def test_get_framework_stride_4q(self):
        pack = _make_pack("stride-4q", "4QF + STRIDE")
        register_framework(pack)
        assert get_framework("stride-4q") is pack

    def test_get_framework_pasta(self):
        pack = _make_pack("pasta", "PASTA")
        register_framework(pack)
        assert get_framework("pasta") is pack

    def test_get_framework_linddun(self):
        pack = _make_pack("linddun", "LINDDUN Pro")
        register_framework(pack)
        assert get_framework("linddun") is pack

    def test_get_framework_maestro(self):
        pack = _make_pack("maestro", "MAESTRO")
        register_framework(pack)
        assert get_framework("maestro") is pack

    def test_get_framework_invalid_name_raises_value_error(self):
        register_framework(_make_pack("stride-4q", "4QF + STRIDE"))
        with pytest.raises(ValueError, match="Unknown framework 'bogus'"):
            get_framework("bogus")

    def test_get_framework_invalid_name_lists_available(self):
        register_framework(_make_pack("stride-4q", "4QF + STRIDE"))
        register_framework(_make_pack("pasta", "PASTA"))
        with pytest.raises(ValueError, match="pasta") as exc_info:
            get_framework("unknown")
        assert "stride-4q" in str(exc_info.value)

    def test_get_framework_empty_registry_raises(self):
        _REGISTRY.clear()
        with pytest.raises(ValueError):
            get_framework("stride-4q")


class TestListFrameworks:
    def test_list_frameworks_returns_all_four(self):
        packs = list_frameworks()
        names = {p.name for p in packs}
        assert names == {"stride-4q", "pasta", "linddun", "maestro"}

    def test_list_frameworks_returns_framework_pack_instances(self):
        packs = list_frameworks()
        assert all(isinstance(p, FrameworkPack) for p in packs)

    def test_list_frameworks_each_has_name(self):
        packs = list_frameworks()
        assert all(p.name for p in packs)

    def test_list_frameworks_each_has_display_name(self):
        packs = list_frameworks()
        assert all(p.display_name for p in packs)

    def test_list_frameworks_each_has_description(self):
        packs = list_frameworks()
        assert all(p.description for p in packs)
