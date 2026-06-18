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
    )


def _make_pack(name: str, display_name: str) -> FrameworkPack:
    return FrameworkPack(
        name=name,
        display_name=display_name,
        description=f"{display_name} description",
        stages=[_make_stage(1)],
        report_stage=_make_stage(99),
    )


@pytest.fixture(autouse=True)
def clean_registry():
    """Snapshot and restore registry state around each test."""
    original = dict(_REGISTRY)
    yield
    _REGISTRY.clear()
    _REGISTRY.update(original)


class TestGetFramework:
    def test_returns_registered_pack(self):
        pack = _make_pack("stride-4q", "4QF + STRIDE")
        register_framework(pack)
        assert get_framework("stride-4q") is pack

    def test_unknown_name_raises_value_error(self):
        register_framework(_make_pack("stride-4q", "4QF + STRIDE"))
        with pytest.raises(ValueError, match="Unknown framework 'bogus'"):
            get_framework("bogus")

    def test_unknown_name_lists_available(self):
        register_framework(_make_pack("stride-4q", "4QF + STRIDE"))
        register_framework(_make_pack("pasta", "PASTA"))
        with pytest.raises(ValueError) as exc_info:
            get_framework("unknown")
        message = str(exc_info.value)
        assert "stride-4q" in message
        assert "pasta" in message

    def test_empty_registry_raises(self):
        _REGISTRY.clear()
        with pytest.raises(ValueError):
            get_framework("stride-4q")


class TestBuiltInRegistration:
    def test_built_ins_are_registered(self):
        names = {p.name for p in list_frameworks()}
        assert names == {"stride-4q", "pasta"}

    def test_every_built_in_points_at_a_skill(self):
        """Model B requires every registered pack to name a providing skill."""
        assert all(p.skill_name for p in list_frameworks())
