"""Tests for 4QF+STRIDE Stage 2 — Threat Identification prompt template."""

from threatsmith.frameworks.references.owasp import OWASP_WEB_TOP_10
from threatsmith.frameworks.references.stride_categories import STRIDE_CATEGORIES
from threatsmith.frameworks.stride_4q.stage_02_threat_identification import (
    STAGE_PROMPT,
    build_prompt,
)
from threatsmith.frameworks.types import StageContext


class TestBuildPrompt:
    def test_returns_string(self):
        result = build_prompt(StageContext())
        assert isinstance(result, str)

    def test_with_all_context_types(self):
        """Verify prompt includes prior output, references, and scanner context."""
        result = build_prompt(
            StageContext(
                prior_outputs={"stage_01_output": "## System Model\nComponents..."},
                references=[STRIDE_CATEGORIES, OWASP_WEB_TOP_10],
                scanners_available=["semgrep"],
            )
        )
        assert "## System Model" in result
        assert "Components..." in result
        assert "STRIDE" in result
        assert "Broken Access Control" in result
        assert "Semgrep" in result

    def test_stride_reference_in_output(self):
        result = build_prompt(StageContext(references=[STRIDE_CATEGORIES]))
        assert "Spoofing" in result
        assert "Tampering" in result
        assert "Repudiation" in result
        assert "Information Disclosure" in result
        assert "Denial of Service" in result
        assert "Elevation of Privilege" in result
        assert "REFERENCE CHECKLISTS" in result

    def test_owasp_reference_in_output(self):
        result = build_prompt(StageContext(references=[OWASP_WEB_TOP_10]))
        assert "Broken Access Control" in result
        assert "REFERENCE CHECKLISTS" in result

    def test_scanner_snippet_present_when_scanners_available(self):
        result = build_prompt(StageContext(scanners_available=["semgrep"]))
        assert "SCANNER INSTRUCTIONS" in result
        assert "Semgrep" in result

    def test_scanner_snippet_absent_when_no_scanners(self):
        result = build_prompt(StageContext())
        assert "SCANNER INSTRUCTIONS" not in result

    def test_scanner_snippet_absent_when_empty_list(self):
        result = build_prompt(StageContext(scanners_available=[]))
        assert "SCANNER INSTRUCTIONS" not in result

    def test_prior_stage_output_injected(self):
        result = build_prompt(
            StageContext(prior_outputs={"stage_01_output": "System model content here"})
        )
        assert "PRIOR STAGE FINDINGS" in result
        assert "<stage_01_system_model>" in result
        assert "System model content here" in result
        assert "</stage_01_system_model>" in result

    def test_prior_stage_absent_when_no_output(self):
        result = build_prompt(StageContext())
        assert "PRIOR STAGE FINDINGS" not in result
        assert "<stage_01_system_model>" not in result

    def test_prior_stage_absent_when_empty_string(self):
        result = build_prompt(StageContext(prior_outputs={"stage_01_output": ""}))
        assert "PRIOR STAGE FINDINGS" not in result

    def test_references_absent_when_none(self):
        result = build_prompt(StageContext())
        assert "REFERENCE CHECKLISTS" not in result

    def test_references_absent_when_empty_list(self):
        result = build_prompt(StageContext(references=[]))
        assert "REFERENCE CHECKLISTS" not in result

    def test_output_file_path(self):
        result = build_prompt(StageContext())
        assert "threatmodel/02-threat-identification.md" in result

    def test_custom_output_dir(self):
        result = build_prompt(StageContext(), output_dir="output")
        assert "output/02-threat-identification.md" in result

    def test_output_dir_trailing_slash_normalized(self):
        result = build_prompt(StageContext(), output_dir="output/")
        assert "output/02-threat-identification.md" in result
        assert "output//02-threat-identification.md" not in result

    def test_no_raw_placeholders_in_output(self):
        result = build_prompt(StageContext())
        assert "{prior_stages_section}" not in result
        assert "{references_section}" not in result
        assert "{scanner_section}" not in result
        assert "{output_dir}" not in result

    def test_contains_four_question_framework_context(self):
        result = build_prompt(StageContext())
        assert "What can go wrong?" in result

    def test_multiple_scanners(self):
        result = build_prompt(StageContext(scanners_available=["semgrep", "trivy"]))
        assert "Semgrep" in result
        assert "Trivy" in result


class TestStagePrompt:
    def test_is_non_empty_string(self):
        assert isinstance(STAGE_PROMPT, str)
        assert len(STAGE_PROMPT) > 0

    def test_contains_placeholders(self):
        assert "{prior_stages_section}" in STAGE_PROMPT
        assert "{references_section}" in STAGE_PROMPT
        assert "{scanner_section}" in STAGE_PROMPT
        assert "{output_dir}" in STAGE_PROMPT
