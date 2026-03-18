import threatsmith.frameworks._built_in  # noqa: F401 — triggers built-in registrations
from threatsmith.frameworks.models import (
    _REGISTRY,
    FrameworkPack,
    StageSpec,
    get_framework,
    list_frameworks,
    register_framework,
)

__all__ = [
    "FrameworkPack",
    "StageSpec",
    "_REGISTRY",
    "get_framework",
    "list_frameworks",
    "register_framework",
]
