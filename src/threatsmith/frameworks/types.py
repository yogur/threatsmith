from __future__ import annotations

from dataclasses import dataclass


@dataclass
class StageSpec:
    number: int
    name: str
    output_file: str


@dataclass
class FrameworkPack:
    name: str
    display_name: str
    description: str
    stages: list[StageSpec]
    report_stage: StageSpec
    skill_name: str = ""


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
