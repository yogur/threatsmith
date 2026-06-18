"""Tests for 4QF+STRIDE pack builder."""

import pytest

from threatsmith.frameworks.stride_4q import build_stride_4q_pack


@pytest.fixture()
def pack():
    return build_stride_4q_pack()


def test_pack_name(pack):
    assert pack.name == "stride-4q"


def test_pack_display_name(pack):
    assert pack.display_name == "4QF + STRIDE"


def test_pack_skill_name(pack):
    assert pack.skill_name == "threatsmith-stride-4q"


def test_pack_description_nonempty(pack):
    assert pack.description


def test_pack_stage_count(pack):
    assert len(pack.stages) == 4


def test_pack_has_report_stage(pack):
    assert pack.report_stage is not None


def test_pack_stage_numbers(pack):
    assert [s.number for s in pack.stages] == [1, 2, 3, 4]


def test_pack_report_stage_number(pack):
    assert pack.report_stage.number == 5


def test_pack_stage_output_files(pack):
    expected = [
        "01-system-model.md",
        "02-threat-identification.md",
        "03-mitigations.md",
        "04-validation.md",
    ]
    assert [s.output_file for s in pack.stages] == expected


def test_pack_report_stage_output_file(pack):
    assert pack.report_stage.output_file == "05-report.md"
