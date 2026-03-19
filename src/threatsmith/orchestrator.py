"""Orchestrator — runs all framework stages plus report consolidation sequentially."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from threatsmith.assembler import assemble_prompt
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
    scanner_info: dict | None = None
    user_objectives: dict | None = None
    _prior_outputs: dict[str, str] = field(default_factory=dict, init=False)

    @property
    def stages_completed(self) -> int:
        """Number of pipeline stages that completed successfully."""
        return len(self._prior_outputs)

    def _output_file_path(self, filename: str) -> str:
        """Absolute path to a deliverable file within the repo's output directory."""
        return os.path.join(self.repo_path, self.output_dir, filename)

    def _run_stage(self, stage: StageSpec) -> bool:
        """Execute a single stage.

        Returns True on success, False on failure.
        """
        output_path = self._output_file_path(stage.output_file)
        output_key = f"stage_{stage.number:02d}_output"

        logger.info("Stage %d — starting", stage.number)

        prompt = assemble_prompt(
            stage=stage,
            pack=self.pack,
            prior_outputs=self._prior_outputs,
            scanner_info=self.scanner_info,
            user_objectives=self.user_objectives,
            output_dir=self.output_dir,
        )

        exit_code = self.engine.execute(prompt, self.repo_path, self.output_dir)

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

        # Success — read deliverable and accumulate context
        with open(output_path) as fh:
            content = fh.read()
        self._prior_outputs[output_key] = content

        logger.info("Stage %d — complete", stage.number)
        logger.debug(
            "Stage %d: accumulated context %d chars",
            stage.number,
            sum(len(v) for v in self._prior_outputs.values()),
        )
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
