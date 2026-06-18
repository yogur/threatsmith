"""Orchestrator — runs all framework stages plus report consolidation sequentially."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from threatsmith.engines.base import Engine
from threatsmith.frameworks import FrameworkPack, StageSpec

logger = logging.getLogger(__name__)


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


@dataclass
class Orchestrator:
    """Runs a full threat modeling pipeline against a target repository."""

    engine: Engine
    repo_path: str
    pack: FrameworkPack
    output_dir: str = "threatmodel"
    mode: str = "from-code"
    user_objectives: dict | None = None
    _stages_completed: int = field(default=0, init=False)

    @property
    def stages_completed(self) -> int:
        """Number of pipeline stages that completed successfully."""
        return self._stages_completed

    def _output_file_path(self, filename: str) -> str:
        """Absolute path to a deliverable file within the repo's output directory."""
        return os.path.join(self.repo_path, self.output_dir, filename)

    def _run_stage(self, stage: StageSpec) -> bool:
        """Execute a single stage.

        Returns True on success, False on failure.
        """
        output_path = self._output_file_path(stage.output_file)

        logger.info("Stage %d — starting", stage.number)

        instruction = compose_stage_instruction(
            stage=stage,
            pack=self.pack,
            mode=self.mode,
            output_dir=self.output_dir,
            user_objectives=self.user_objectives,
        )

        exit_code = self.engine.execute(instruction, self.repo_path, self.output_dir)

        if exit_code != 0:
            logger.error(
                "Stage %d: engine returned exit code %d — aborting",
                stage.number,
                exit_code,
            )
            return False

        if not os.path.isfile(output_path):
            logger.error(
                "Stage %d: output file not found — aborting",
                stage.number,
            )
            return False

        self._stages_completed += 1
        logger.info("Stage %d — complete", stage.number)
        return True

    def run(self) -> int:
        """Execute all pipeline stages sequentially.

        Returns:
            0 on full success, 1 if any stage fails.
        """
        all_stages = list(self.pack.stages) + [self.pack.report_stage]

        for stage in all_stages:
            success = self._run_stage(stage)
            if not success:
                logger.error(
                    "Stage %d failed — aborting pipeline.",
                    stage.number,
                )
                return 1

        logger.info("Pipeline complete.")
        return 0
