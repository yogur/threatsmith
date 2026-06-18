"""Assembler — composes per-stage instructions for the engine to run an installed skill."""

from threatsmith.frameworks.types import FrameworkPack, StageSpec


def compose_stage_instruction(
    stage: StageSpec,
    pack: FrameworkPack,
    mode: str = "from-code",
    output_dir: str = "threatmodel",
    user_objectives: dict | None = None,
) -> str:
    """Compose a per-stage instruction for Model B skill-driven execution.

    The instruction names the installed skill, the stage to execute, the mode,
    the output directory, and the location of prior stage outputs (by file pointer —
    no prior-stage text is inlined).

    Args:
        stage: The StageSpec to execute.
        pack: The FrameworkPack that owns this stage (provides the skill name).
        mode: Generation mode — 'from-code' or 'from-docs'.
        output_dir: Output directory for deliverables (defaults to 'threatmodel').
        user_objectives: Optional dict with 'business_objectives' and/or
                         'security_objectives' strings.

    Returns:
        A single instruction string ready for engine.execute().
    """
    safe_dir = output_dir.rstrip("/")
    instruction = (
        f"Use skill `{pack.skill_name}`. "
        f"Run stage {stage.number:02d} ({stage.name}) in {mode} mode. "
        f"Output directory: {safe_dir}/. "
        f"Prior stage outputs, if any, are in {safe_dir}/ — read from there as needed. "
        "This is a non-interactive single-stage run; proceed to completion without pausing."
    )

    objectives = user_objectives or {}
    business = objectives.get("business_objectives") or None
    security = objectives.get("security_objectives") or None

    if business or security:
        instruction += "\n\nUser context:"
        if business:
            instruction += f"\n- Business objectives: {business}"
        if security:
            instruction += f"\n- Security objectives: {security}"

    return instruction
