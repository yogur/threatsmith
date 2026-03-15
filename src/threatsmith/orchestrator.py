"""Orchestrator — runs all 7 PASTA stages plus report consolidation sequentially."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from threatsmith.engines.base import Engine
from threatsmith.prompts.assembler import assemble_prompt

logger = logging.getLogger(__name__)

# Maps stage_number → (output filename, prior_outputs key)
_STAGE_FILES: dict[int, tuple[str, str]] = {
    1: ("01-objectives.md", "stage_01_output"),
    2: ("02-technical-scope.md", "stage_02_output"),
    3: ("03-application-decomposition.md", "stage_03_output"),
    4: ("04-threat-analysis.md", "stage_04_output"),
    5: ("05-vulnerability-analysis.md", "stage_05_output"),
    6: ("06-attack-modeling.md", "stage_06_output"),
    7: ("07-risk-and-impact-analysis.md", "stage_07_output"),
    8: ("08-report.md", "stage_08_output"),
}


@dataclass
class Orchestrator:
    """Runs the full PASTA threat modeling pipeline against a target repository."""

    engine: Engine
    repo_path: str
    output_dir: str = "threatmodel"
    scanner_info: dict | None = None
    user_objectives: dict | None = None
    commit_hash: str | None = None
    _prior_outputs: dict[str, str] = field(default_factory=dict, init=False)

    def _output_file_path(self, filename: str) -> str:
        """Absolute path to a deliverable file within the repo's output directory."""
        return os.path.join(self.repo_path, self.output_dir, filename)

    def _run_stage(self, stage_number: int) -> bool:
        """Execute a single stage with one retry on failure.

        Returns True on success, False if both attempts fail.
        """
        filename, output_key = _STAGE_FILES[stage_number]
        output_path = self._output_file_path(filename)

        for attempt in range(1, 3):  # attempts 1 and 2
            if attempt == 1:
                logger.info("[ThreatSmith] Stage %d — starting", stage_number)
            else:
                logger.info(
                    "[ThreatSmith] Stage %d — retrying (attempt 2/2)", stage_number
                )

            prompt = assemble_prompt(
                stage_number=stage_number,
                prior_outputs=self._prior_outputs,
                scanner_info=self.scanner_info,
                user_objectives=self.user_objectives,
                commit_hash=self.commit_hash,
                output_dir=self.output_dir,
            )

            exit_code = self.engine.execute(prompt, self.repo_path)

            if exit_code != 0:
                if attempt == 1:
                    logger.warning(
                        "[ThreatSmith] Stage %d: engine returned exit code %d — retrying",
                        stage_number,
                        exit_code,
                    )
                    continue
                logger.error(
                    "[ThreatSmith] Stage %d: engine returned exit code %d — aborting",
                    stage_number,
                    exit_code,
                )
                return False

            if not os.path.isfile(output_path):
                if attempt == 1:
                    logger.warning(
                        "[ThreatSmith] Stage %d: output file not found — retrying",
                        stage_number,
                    )
                    continue
                logger.error(
                    "[ThreatSmith] Stage %d: output file not found — aborting",
                    stage_number,
                )
                return False

            # Success — read deliverable and accumulate context
            with open(output_path) as fh:
                content = fh.read()
            self._prior_outputs[output_key] = content

            logger.info("[ThreatSmith] Stage %d — complete", stage_number)
            logger.debug(
                "[ThreatSmith] Stage %d: accumulated context %d chars",
                stage_number,
                sum(len(v) for v in self._prior_outputs.values()),
            )
            return True

        return False  # unreachable but satisfies type checker

    def run(self) -> int:
        """Execute all 8 pipeline stages sequentially.

        Returns:
            0 on full success, 1 if any stage fails after retry.
        """
        for stage_number in range(1, 9):
            success = self._run_stage(stage_number)
            if not success:
                logger.error(
                    "[ThreatSmith] Stage %d failed after retry — aborting pipeline.",
                    stage_number,
                )
                return 1

        logger.info("[ThreatSmith] Pipeline complete.")
        return 0
