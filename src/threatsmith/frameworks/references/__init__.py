"""Shared reference constants and conditional injection utilities."""

from threatsmith.frameworks.references.conditions import (
    API_KEYWORDS,
    LLM_KEYWORDS,
    MOBILE_KEYWORDS,
    evaluate_reference_conditions,
)

__all__ = [
    "API_KEYWORDS",
    "LLM_KEYWORDS",
    "MOBILE_KEYWORDS",
    "evaluate_reference_conditions",
]
