"""Logging configuration for ThreatSmith."""

from __future__ import annotations

import logging
import sys


class ThreatSmithFormatter(logging.Formatter):
    """Custom formatter that adds [ThreatSmith] prefix and marks errors clearly."""

    LEVEL_COLORS = {
        logging.ERROR: "\033[91m",  # bright red
        logging.WARNING: "\033[93m",  # bright yellow
        logging.DEBUG: "\033[94m",  # bright blue
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with app name and colored error indicators."""
        msg = record.getMessage()
        level_name = record.levelname

        # Add [ThreatSmith] prefix
        prefix = "[ThreatSmith]"

        # Add level indicator for errors and warnings
        if record.levelno >= logging.WARNING:
            if sys.stderr.isatty():
                color = self.LEVEL_COLORS.get(record.levelno, "")
                indicator = f"{color}{level_name}:{self.RESET}"
                return f"{prefix} {indicator} {msg}"
            return f"{prefix} {msg}"

        return f"{prefix} {msg}"


def configure_logging(verbose: bool = False) -> None:
    """Configure ThreatSmith logging with custom formatter.

    Args:
        verbose: If True, set logging level to DEBUG; otherwise INFO.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        handlers=[logging.StreamHandler(sys.stderr)],
        force=True,
    )
    handler = logging.root.handlers[0]
    handler.setFormatter(ThreatSmithFormatter())
