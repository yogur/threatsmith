"""Typed context dataclasses for each PASTA stage's build_prompt function."""

from dataclasses import dataclass


@dataclass
class ObjectivesContext:
    """Context for Stage 1 — Define Objectives."""

    business_objectives: str | None = None
    security_objectives: str | None = None


@dataclass
class TechnicalScopeContext:
    """Context for Stage 2 — Define Technical Scope."""

    stage_01_output: str | None = None


@dataclass
class DecompositionContext:
    """Context for Stage 3 — Application Decomposition."""

    stage_01_output: str | None = None
    stage_02_output: str | None = None


@dataclass
class ThreatAnalysisContext:
    """Context for Stage 4 — Threat Analysis."""

    stage_01_output: str | None = None
    stage_02_output: str | None = None
    stage_03_output: str | None = None


@dataclass
class VulnerabilityContext:
    """Context for Stage 5 — Vulnerability and Weakness Analysis."""

    stage_01_output: str | None = None
    stage_02_output: str | None = None
    stage_03_output: str | None = None
    stage_04_output: str | None = None
    scanners_available: list[str] | None = None


@dataclass
class AttackModelingContext:
    """Context for Stage 6 — Attack Modeling."""

    stage_01_output: str | None = None
    stage_02_output: str | None = None
    stage_03_output: str | None = None
    stage_04_output: str | None = None
    stage_05_output: str | None = None


@dataclass
class RiskImpactContext:
    """Context for Stage 7 — Risk and Impact Analysis."""

    stage_01_output: str | None = None
    stage_02_output: str | None = None
    stage_03_output: str | None = None
    stage_04_output: str | None = None
    stage_05_output: str | None = None
    stage_06_output: str | None = None


@dataclass
class ReportContext:
    """Context for Stage 8 — Report Consolidation."""

    stage_01_output: str | None = None
    stage_02_output: str | None = None
    stage_03_output: str | None = None
    stage_04_output: str | None = None
    stage_05_output: str | None = None
    stage_06_output: str | None = None
    stage_07_output: str | None = None
