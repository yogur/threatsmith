from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass
class StageSpec:
    number: int
    name: str
    output_file: str
    build_prompt: Callable


@dataclass
class FrameworkPack:
    name: str
    display_name: str
    description: str
    stages: list[StageSpec]
    report_stage: StageSpec
    scanner_stages: list[int] = field(default_factory=list)
    reference_sets: dict[int, list[dict]] = field(default_factory=dict)


_REGISTRY: dict[str, FrameworkPack] = {}


def register_framework(pack: FrameworkPack) -> None:
    _REGISTRY[pack.name] = pack


def get_framework(name: str) -> FrameworkPack:
    if name in _REGISTRY:
        return _REGISTRY[name]
    available = ", ".join(sorted(_REGISTRY.keys()))
    raise ValueError(f"Unknown framework '{name}'. Available frameworks: {available}")


def list_frameworks() -> list[FrameworkPack]:
    return list(_REGISTRY.values())
