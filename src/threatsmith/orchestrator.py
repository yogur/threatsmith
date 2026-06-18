"""Orchestrator — runs all framework stages plus report consolidation sequentially."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from threatsmith.assembler import compose_stage_instruction
from threatsmith.engines.base import Engine
from threatsmith.frameworks.types import FrameworkPack, StageSpec

logger = logging.getLogger(__name__)


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
