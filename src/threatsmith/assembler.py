"""Prompt assembler — framework-agnostic prompt assembly from stage specs."""

from threatsmith.frameworks.references.conditions import evaluate_reference_conditions
from threatsmith.frameworks.types import FrameworkPack, StageContext, StageSpec


def assemble_prompt(
    stage: StageSpec,
    pack: FrameworkPack,
    prior_outputs: dict[str, str] | None = None,
    scanner_info: dict | None = None,
    user_objectives: dict | None = None,
    output_dir: str = "threatmodel",
) -> str:
    """Assemble a complete prompt for the given stage.

    Args:
        stage: The StageSpec to build a prompt for.
        pack: The FrameworkPack that owns this stage.
        prior_outputs: Mapping of stage output keys to markdown strings, e.g.
                       {"stage_01_output": "...", "stage_02_output": "..."}.
        scanner_info: Dict with "available" and "unavailable" scanner name lists,
                      as returned by detect_scanners().
        user_objectives: Dict with optional "business_objectives" and
                         "security_objectives" strings.
        output_dir: Output directory for deliverables (defaults to "threatmodel").

    Returns:
        The fully assembled prompt string ready for engine.execute().
    """
    po = prior_outputs or {}
    si = scanner_info or {}

    # Evaluate reference conditions for this stage
    references: list[str] = []
    if stage.number in pack.reference_sets:
        references = evaluate_reference_conditions(
            pack.reference_sets[stage.number], po
        )

    # Populate scanners if this is a scanner-eligible stage
    scanners_available = None
    if stage.number in pack.scanner_stages:
        scanners_available = si.get("available") or None

    context = StageContext(
        user_objectives=user_objectives or None,
        prior_outputs=po,
        scanners_available=scanners_available,
        references=references,
    )

    return stage.build_prompt(context, output_dir=output_dir)
