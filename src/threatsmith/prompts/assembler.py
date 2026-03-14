"""Prompt assembler — selects the correct stage template and injects dynamic context."""

from threatsmith.prompts import (
    stage_01_objectives,
    stage_02_technical_scope,
    stage_03_decomposition,
    stage_04_threat_analysis,
    stage_05_vulnerability,
    stage_06_attack_modeling,
    stage_07_risk_impact,
    stage_08_report,
)
from threatsmith.prompts.contexts import (
    AttackModelingContext,
    DecompositionContext,
    ObjectivesContext,
    ReportContext,
    RiskImpactContext,
    TechnicalScopeContext,
    ThreatAnalysisContext,
    VulnerabilityContext,
)


def assemble_prompt(
    stage_number: int,
    prior_outputs: dict[str, str] | None = None,
    scanner_info: dict | None = None,
    user_objectives: dict | None = None,
    commit_hash: str | None = None,  # noqa: ARG001 — reserved for future use
    output_dir: str = "threatmodel",
) -> str:
    """Assemble a complete prompt for the given PASTA stage.

    Args:
        stage_number: PASTA stage number (1-8).
        prior_outputs: Mapping of stage output keys to markdown strings, e.g.
                       {"stage_01_output": "...", "stage_02_output": "..."}.
        scanner_info: Dict with "available" and "unavailable" scanner name lists,
                      as returned by detect_scanners(). Used for Stage 5.
        user_objectives: Dict with optional "business_objectives" and
                         "security_objectives" strings. Used for Stage 1.
        commit_hash: Git commit hash of the analysed repository. Reserved for
                     future prompt injection; accepted but not currently injected.
        output_dir: Output directory for deliverables (defaults to "threatmodel").

    Returns:
        The fully assembled prompt string ready for engine.execute().

    Raises:
        ValueError: If stage_number is not in the range 1-8.
    """
    po = prior_outputs or {}
    uo = user_objectives or {}
    si = scanner_info or {}

    if stage_number == 1:
        context = ObjectivesContext(
            business_objectives=uo.get("business_objectives") or None,
            security_objectives=uo.get("security_objectives") or None,
        )
        return stage_01_objectives.build_prompt(context, output_dir=output_dir)

    if stage_number == 2:
        context = TechnicalScopeContext(
            stage_01_output=po.get("stage_01_output") or None,
        )
        return stage_02_technical_scope.build_prompt(context, output_dir=output_dir)

    if stage_number == 3:
        context = DecompositionContext(
            stage_01_output=po.get("stage_01_output") or None,
            stage_02_output=po.get("stage_02_output") or None,
        )
        return stage_03_decomposition.build_prompt(context, output_dir=output_dir)

    if stage_number == 4:
        context = ThreatAnalysisContext(
            stage_01_output=po.get("stage_01_output") or None,
            stage_02_output=po.get("stage_02_output") or None,
            stage_03_output=po.get("stage_03_output") or None,
        )
        return stage_04_threat_analysis.build_prompt(context, output_dir=output_dir)

    if stage_number == 5:
        context = VulnerabilityContext(
            stage_01_output=po.get("stage_01_output") or None,
            stage_02_output=po.get("stage_02_output") or None,
            stage_03_output=po.get("stage_03_output") or None,
            stage_04_output=po.get("stage_04_output") or None,
            scanners_available=si.get("available") or None,
        )
        return stage_05_vulnerability.build_prompt(context, output_dir=output_dir)

    if stage_number == 6:
        context = AttackModelingContext(
            stage_01_output=po.get("stage_01_output") or None,
            stage_02_output=po.get("stage_02_output") or None,
            stage_03_output=po.get("stage_03_output") or None,
            stage_04_output=po.get("stage_04_output") or None,
            stage_05_output=po.get("stage_05_output") or None,
        )
        return stage_06_attack_modeling.build_prompt(context, output_dir=output_dir)

    if stage_number == 7:
        context = RiskImpactContext(
            stage_01_output=po.get("stage_01_output") or None,
            stage_02_output=po.get("stage_02_output") or None,
            stage_03_output=po.get("stage_03_output") or None,
            stage_04_output=po.get("stage_04_output") or None,
            stage_05_output=po.get("stage_05_output") or None,
            stage_06_output=po.get("stage_06_output") or None,
        )
        return stage_07_risk_impact.build_prompt(context, output_dir=output_dir)

    if stage_number == 8:
        context = ReportContext(
            stage_01_output=po.get("stage_01_output") or None,
            stage_02_output=po.get("stage_02_output") or None,
            stage_03_output=po.get("stage_03_output") or None,
            stage_04_output=po.get("stage_04_output") or None,
            stage_05_output=po.get("stage_05_output") or None,
            stage_06_output=po.get("stage_06_output") or None,
            stage_07_output=po.get("stage_07_output") or None,
        )
        return stage_08_report.build_prompt(context, output_dir=output_dir)

    raise ValueError(f"stage_number must be between 1 and 8, got {stage_number}")
