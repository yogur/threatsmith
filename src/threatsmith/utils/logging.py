"""
Centralized logging configuration using structlog.
Provides get_logger() function and core structlog setup for threatsmith package.
"""

import logging
import sys
from typing import Optional
import structlog
from structlog.dev import ConsoleRenderer


def get_logger(name: Optional[str] = None) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance scoped to threatsmith package."""
    if name and name.startswith("threatsmith."):
        logger_name = name
    elif name:
        logger_name = f"threatsmith.{name}"
    else:
        logger_name = "threatsmith"

    return structlog.get_logger(logger_name)


# Configure root logger to suppress most third-party logs
logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=logging.WARNING,  # Only WARNING+ for all loggers by default
)

structlog.configure(
    processors=[
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        ConsoleRenderer(colors=True),  # Colored output
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    cache_logger_on_first_use=True,
)
