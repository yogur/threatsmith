"""Tests for STRIDE category reference constants."""

from threatsmith.prompts.references.stride_categories import STRIDE_CATEGORIES


class TestStrideCategories:
    def test_spoofing_present(self):
        assert "Spoofing" in STRIDE_CATEGORIES

    def test_tampering_present(self):
        assert "Tampering" in STRIDE_CATEGORIES

    def test_repudiation_present(self):
        assert "Repudiation" in STRIDE_CATEGORIES

    def test_information_disclosure_present(self):
        assert "Information Disclosure" in STRIDE_CATEGORIES

    def test_denial_of_service_present(self):
        assert "Denial of Service" in STRIDE_CATEGORIES

    def test_elevation_of_privilege_present(self):
        assert "Elevation of Privilege" in STRIDE_CATEGORIES

    def test_all_six_initial_letters_present(self):
        # Verify the STRIDE acronym is represented
        for letter in ("S", "T", "R", "I", "D", "E"):
            assert letter in STRIDE_CATEGORIES, f"Initial letter '{letter}' not found"
