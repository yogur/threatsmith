"""
Main CLI entry point for ThreatSmith
"""

import argparse
import logging
import sys
from pathlib import Path

from threatsmith.orchestrator import ThreatAnalysisOrchestrator
from threatsmith.utils.logging import get_logger


def setup_logging(verbose: bool = False) -> None:
    """Configure logging level based on verbosity."""
    if verbose:
        # Enable DEBUG level for detailed logging
        logging.getLogger("threatsmith").setLevel(logging.DEBUG)
    else:
        # Set application to INFO level for normal operation
        logging.getLogger("threatsmith").setLevel(logging.INFO)


def validate_path(path_str: str) -> Path:
    """Validate and return Path object for the target path."""
    path = Path(path_str).resolve()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Path does not exist: {path}")
    return path


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="ThreatSmith - AI-powered secure code review and threat analysis engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/project
  %(prog)s /path/to/project --model openai:gpt-4.1
  %(prog)s /path/to/project --business_objectives "Secure user data" --verbose
          %(prog)s ./my-app --model google_genai:gemini-2.5-flash --security_objectives "Prevent data breaches" --save-stage-outputs

Supported models (provider:model-id) and required env vars:
  - openai (env: OPENAI_API_KEY): e.g., openai:gpt-4.1
  - anthropic (env: ANTHROPIC_API_KEY): e.g., anthropic:claude-sonnet-4-0
  - google_genai (env: GOOGLE_API_KEY): e.g., google_genai:gemini-2.5-flash
        """.strip(),
    )

    # Required arguments
    parser.add_argument(
        "path", type=validate_path, help="Path to the project/application to analyze"
    )

    # Optional arguments
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        required=True,
        help=(
            "AI model to use for analysis (required). Format: 'provider:model-id'. "
            "Examples: 'openai:gpt-4.1', 'anthropic:claude-sonnet-4-0', "
            "'google_genai:gemini-2.5-flash'. Env vars: OPENAI_API_KEY, "
            "ANTHROPIC_API_KEY, GOOGLE_API_KEY."
        ),
    )

    parser.add_argument(
        "--business_objectives",
        type=str,
        help="Optional business objectives for the security analysis",
    )

    parser.add_argument(
        "--security_objectives",
        type=str,
        help="Optional security objectives for the analysis",
    )

    parser.add_argument(
        "--output_dir",
        type=Path,
        default=Path("./output"),
        help="Directory to save analysis results (default: ./output)",
    )

    # Verbosity and reporting options
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose (debug) logging"
    )

    parser.add_argument(
        "--save-stage-outputs",
        action="store_true",
        help="Save a second markdown that includes raw outputs from each analysis stage (in addition to the final report)",
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point for the CLI."""
    try:
        args = parse_arguments()

        # Setup logging
        setup_logging(args.verbose)
        logger = get_logger(__name__)

        logger.info("Starting ThreatSmith security analysis")
        logger.debug("Arguments: %s", vars(args))

        # Create orchestrator
        orchestrator = ThreatAnalysisOrchestrator(
            target_path=args.path, model=args.model, output_dir=args.output_dir
        )

        # Run analysis
        logger.info(f"Analyzing target: {args.path}")
        _ = orchestrator.run_analysis(
            business_objectives=args.business_objectives,
            security_objectives=args.security_objectives,
            save_stage_outputs=args.save_stage_outputs,
        )

        logger.info("Analysis completed successfully")

        return 0

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        logger = get_logger(__name__)
        logger.error(f"Analysis failed: {e}")
        if args.verbose if "args" in locals() else False:
            logger.exception("Full error traceback:")
        return 1


if __name__ == "__main__":
    sys.exit(main())
