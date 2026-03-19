"""Tests for 4QF+STRIDE pack builder."""

import pytest

from threatsmith.frameworks.references.owasp import (
    OWASP_API_TOP_10,
    OWASP_LLM_TOP_10,
    OWASP_MOBILE_TOP_10,
    OWASP_WEB_TOP_10,
)
from threatsmith.frameworks.references.stride_categories import STRIDE_CATEGORIES
from threatsmith.frameworks.stride_4q import build_stride_4q_pack


@pytest.fixture()
def pack():
    return build_stride_4q_pack()


def test_pack_name(pack):
    assert pack.name == "stride-4q"


def test_pack_display_name(pack):
    assert pack.display_name == "4QF + STRIDE"


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


def test_pack_scanner_stages(pack):
    assert pack.scanner_stages == [2]


def test_pack_reference_sets_has_stage_2(pack):
    assert 2 in pack.reference_sets


def test_pack_reference_sets_stage_2_has_five_entries(pack):
    assert len(pack.reference_sets[2]) == 5


def test_pack_stage_2_stride_categories_always(pack):
    refs = pack.reference_sets[2]
    stride_entry = next((r for r in refs if r["reference"] == STRIDE_CATEGORIES), None)
    assert stride_entry is not None
    assert stride_entry["condition"] == "always"


def test_pack_stage_2_owasp_web_always(pack):
    refs = pack.reference_sets[2]
    entry = next((r for r in refs if r["reference"] == OWASP_WEB_TOP_10), None)
    assert entry is not None
    assert entry["condition"] == "always"


def test_pack_stage_2_owasp_api_detected(pack):
    refs = pack.reference_sets[2]
    entry = next((r for r in refs if r["reference"] == OWASP_API_TOP_10), None)
    assert entry is not None
    assert entry["condition"] == "api_detected"


def test_pack_stage_2_owasp_llm_detected(pack):
    refs = pack.reference_sets[2]
    entry = next((r for r in refs if r["reference"] == OWASP_LLM_TOP_10), None)
    assert entry is not None
    assert entry["condition"] == "llm_detected"


def test_pack_stage_2_owasp_mobile_detected(pack):
    refs = pack.reference_sets[2]
    entry = next((r for r in refs if r["reference"] == OWASP_MOBILE_TOP_10), None)
    assert entry is not None
    assert entry["condition"] == "mobile_detected"


def test_pack_stages_have_build_prompt_callables(pack):
    for stage in pack.stages:
        assert callable(stage.build_prompt)


def test_pack_report_stage_has_build_prompt_callable(pack):
    assert callable(pack.report_stage.build_prompt)


def test_pack_no_other_reference_sets(pack):
    # Only stage 2 should have reference sets
    assert list(pack.reference_sets.keys()) == [2]
