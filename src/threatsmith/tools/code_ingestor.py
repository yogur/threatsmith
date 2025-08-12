from pathlib import Path
from typing import List, Set, Annotated, Optional, Any

from langchain_core.tools import BaseTool, tool
from langchain_core.tools.base import BaseToolkit
from pydantic import Field, model_validator

from threatsmith.utils.logging import get_logger
from gitingest import ingest


EXCLUDED_PATTERNS = {
    "uv.lock",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "node_modules",
    ".git",
    "__pycache__",
    ".pytest_cache",
    "*.pyc",
    "*.pyo",
    "*.pyd",
    ".env",
    ".venv",
}


class CodeIngestorToolkit(BaseToolkit):
    """
    A LangChain toolkit for secure code analysis using gitingest.

    This toolkit provides three tools for analyzing codebases:
    - get_code_summary: Get repository metadata and statistics
    - get_code_tree: Get directory structure and file hierarchy
    - get_code_content: Get actual file contents

    Security: All paths are validated against a parent directory to prevent
    unauthorized access outside the specified scope.
    """

    parent_path: Path = Field(
        description="The parent directory that constrains all tool operations"
    )
    max_file_size: int = Field(
        default=5 * 1024 * 1024, description="Maximum file size in bytes to process"
    )
    exclude_patterns: Set[str] = Field(
        default_factory=lambda: EXCLUDED_PATTERNS,
        description="Set of patterns to exclude from analysis",
    )
    logger: Any = Field(
        default_factory=lambda: get_logger("code_ingestor"),
        description="Logger instance for this toolkit",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_parent_path(cls, data):
        if isinstance(data, dict) and "parent_path" in data:
            parent_path = data["parent_path"]
            if isinstance(parent_path, str):
                data["parent_path"] = Path(parent_path).resolve()
            else:
                data["parent_path"] = parent_path.resolve()
        return data

    def _validate_path(self, path: str) -> Path:
        """
        Validate that the given path is within the parent directory.

        Handles both absolute and relative paths with normalization and fallback logic:
        - Relative paths are resolved relative to the parent directory
        - Absolute paths are validated to ensure they're within the parent directory
        - Includes smart normalization and fallback handling for common LLM mistakes

        Args:
            path: The path to validate (can be absolute or relative)

        Returns:
            Resolved Path object if valid

        Raises:
            ValueError: If path is outside parent directory
        """
        # Normalize the input path
        normalized_path = path.strip()

        # Handle explicit current directory references
        if normalized_path in ("", ".", "./"):
            return self.parent_path

        # Remove trailing slashes for consistency
        normalized_path = normalized_path.rstrip("/\\")

        # Handle current directory references after normalization
        if normalized_path == "":
            return self.parent_path

        input_path = Path(normalized_path)

        if input_path.is_absolute():
            # For absolute paths, resolve and validate they're within parent
            target_path = input_path.resolve()
        else:
            # For relative paths, resolve relative to parent directory
            target_path = (self.parent_path / input_path).resolve()

        # Validate that the final path is within the parent directory
        try:
            target_path.relative_to(self.parent_path)
        except ValueError:
            raise ValueError(
                f"Path '{path}' resolves to '{target_path}' which is outside the allowed parent directory '{self.parent_path}'"
            )

        return target_path

    def get_tools(self) -> List[BaseTool]:
        """Return the list of tools in this toolkit."""
        return [
            self._create_summary_tool(),
            self._create_tree_tool(),
            self._create_content_tool(),
        ]

    def _create_summary_tool(self) -> BaseTool:
        """Create the code summary tool."""

        @tool
        def get_code_summary(
            path: Annotated[
                str,
                """The directory or file path to analyze for summary information.

IMPORTANT PATH USAGE:
- To analyze the CURRENT/ROOT directory: use "." or "" (empty string)
- To analyze a SUBDIRECTORY: use the subdirectory name like "src" or "docs/api"
- Can be absolute or relative to the parent directory

EXAMPLES:
✅ Correct: "." → analyzes the root directory
✅ Correct: "" → analyzes the root directory  
✅ Correct: "src" → analyzes the src/ subdirectory
✅ Correct: "docs/api" → analyzes the docs/api/ subdirectory
❌ Wrong: "parentdirname" → creates duplicate path issues""",
            ],
        ) -> str:
            """
            Get a summary of the code repository including file count and estimated tokens.

            This tool provides high-level metadata about the codebase, including:
            - Repository/directory name
            - Number of files analyzed
            - Estimated token count for LLM processing

            CRITICAL: Use this tool FIRST to determine your ingestion strategy:

            📊 TOKEN-BASED INGESTION STRATEGY:
            • ≤150K tokens: SAFE to ingest entire codebase at once using get_code_content(".")
            • >150K tokens: DIVIDE into logical chunks to stay within context limits

            For large codebases (>150K tokens):
            1. Use get_code_tree to understand structure
            2. Divide into logical chunks (e.g., by major directories/modules)
            3. Aim for ~100-150K tokens per chunk to maintain optimal context
            4. Keep related code together (e.g., a module + its tests)

            You always have autonomy to:
            • Analyze individual files (e.g., "package.json", "main.py")
            • Re-examine specific sections for deeper analysis
            • Focus on particular directories based on your analysis needs

            WORKFLOW: Always start here → check tokens → choose strategy accordingly.
            """
            self.logger.debug("get_code_summary called", path=path)

            try:
                validated_path = self._validate_path(path)

                summary, _, _ = ingest(
                    str(validated_path),
                    max_file_size=self.max_file_size,
                    exclude_patterns=self.exclude_patterns,
                )

                self.logger.debug(
                    "get_code_summary returning result",
                    path=path,
                    summary_length=len(summary),
                )
                return summary
            except Exception as e:
                self.logger.error("Error in get_code_summary", path=path, error=str(e))
                return f"Error analyzing path '{path}': {str(e)}"

        return get_code_summary

    def _create_tree_tool(self) -> BaseTool:
        """Create the code tree tool."""

        @tool
        def get_code_tree(
            path: Annotated[
                str,
                """The directory path to analyze for file structure.

IMPORTANT PATH USAGE:
- To analyze the CURRENT/ROOT directory: use "." or "" (empty string)
- To analyze a SUBDIRECTORY: use the subdirectory name like "src" or "docs/api"
- Can be absolute or relative to the parent directory

EXAMPLES:
✅ Correct: "." → analyzes the root directory structure
✅ Correct: "" → analyzes the root directory structure
✅ Correct: "src" → analyzes the src/ subdirectory structure
✅ Correct: "tests/unit" → analyzes the tests/unit/ subdirectory
❌ Wrong: "parentdirname" → creates duplicate path issues""",
            ],
        ) -> str:
            """
            Get the directory structure and file hierarchy of the codebase.

            This tool provides a hierarchical tree view showing:
            - Directory structure
            - File organization
            - Project layout

            🗂️ STRATEGIC USAGE:
            • ESSENTIAL for large codebases (>150K tokens) to plan logical chunks
            • Helps identify natural boundaries for dividing code analysis
            • Use after get_code_summary to understand how to structure your ingestion

            CHUNKING STRATEGY PLANNING:
            • Identify major directories that can be analyzed separately
            • Look for logical groupings (src/, tests/, docs/, config/)
            • Consider module boundaries and related components
            • Plan chunks that keep related code together for better context

            Use this tool after getting the summary to understand how the code is organized
            and to identify specific files or directories for detailed content analysis.
            """
            self.logger.debug("get_code_tree called", path=path)

            try:
                validated_path = self._validate_path(path)

                _, tree, _ = ingest(
                    str(validated_path),
                    max_file_size=self.max_file_size,
                    exclude_patterns=self.exclude_patterns,
                )

                self.logger.debug(
                    "get_code_tree returning result", path=path, tree_length=len(tree)
                )
                return tree
            except Exception as e:
                self.logger.error("Error in get_code_tree", path=path, error=str(e))
                return f"Error analyzing directory structure for '{path}': {str(e)}"

        return get_code_tree

    def _create_content_tool(self) -> BaseTool:
        """Create the code content tool."""

        @tool
        def get_code_content(
            path: Annotated[
                str,
                """Directory path (to recursively fetch ALL code files within) OR specific file path.

IMPORTANT PATH USAGE:
- To analyze the CURRENT/ROOT directory: use "." or "" (empty string)
- To analyze a SUBDIRECTORY: use the subdirectory name like "src" or "docs/api"  
- To analyze a SPECIFIC FILE: use the file path like "main.py" or "src/config.json"
- Can be absolute or relative to the parent directory

DIRECTORY INPUT: Recursively fetches ALL code files within the directory and any
nested subdirectories in a single operation.

EXAMPLES:
✅ Correct: "." → analyzes all files in root directory recursively
✅ Correct: "" → analyzes all files in root directory recursively
✅ Correct: "src" → analyzes all files in src/ subdirectory recursively
✅ Correct: "main.py" → analyzes the specific main.py file
✅ Correct: "src/config.json" → analyzes the specific config file
❌ Wrong: "parentdirname" → creates duplicate path issues""",
            ],
        ) -> str:
            """
            Get the actual file contents of the codebase.

            🎯 USAGE STRATEGY (based on get_code_summary token count):

            SMALL CODEBASES (≤150K tokens):
            • Use get_code_content(".") to ingest entire codebase at once
            • Most efficient approach for comprehensive analysis

            LARGE CODEBASES (>150K tokens):
            • Divide into logical chunks: get_code_content("src"), get_code_content("tests")
            • Aim for ~100-150K tokens per chunk for optimal context utilization
            • Keep related code together (modules + tests, frontend + backend sections)

            TARGETED ANALYSIS (any codebase size):
            • Individual files: get_code_content("package.json"), get_code_content("main.py")
            • Specific modules: get_code_content("src/auth"), get_code_content("lib/utils")
            • Re-analysis of specific areas for deeper investigation

            DIRECTORY INPUT: Recursively fetches ALL code files within the directory and any
            nested subdirectories in a single operation.

            FILE INPUT: Fetches content of a single specific file.

            This tool provides the full text content including:
            - Source code with proper formatting
            - Documentation files
            - Configuration files
            - Each file clearly delimited with headers showing file paths

            PATH USAGE REMINDERS:
            - Use "." or "" (empty string) to analyze the current/root directory
            - Use subdirectory names like "src" or "docs/api" for subdirectories
            - Never use the parent directory name as a relative path
            """
            self.logger.debug("get_code_content called", path=path)

            try:
                validated_path = self._validate_path(path)

                _, _, content = ingest(
                    str(validated_path),
                    max_file_size=self.max_file_size,
                    exclude_patterns=self.exclude_patterns,
                )

                self.logger.debug(
                    "get_code_content returning result",
                    path=path,
                    content_length=len(content),
                )
                return content
            except Exception as e:
                self.logger.error("Error in get_code_content", path=path, error=str(e))
                return f"Error retrieving content for '{path}': {str(e)}"

        return get_code_content


# Convenience function for quick toolkit creation
def create_code_ingestor_toolkit(
    parent_path: str,
    max_file_size: int = 5 * 1024 * 1024,
    exclude_patterns: Optional[Set[str]] = None,
) -> CodeIngestorToolkit:
    """
    Create a CodeIngestor toolkit with the specified configuration.

    Args:
        parent_path: The parent directory that constrains all tool operations
        max_file_size: Maximum file size in bytes to process (default: 5MB)
        exclude_patterns: Set of patterns to exclude from analysis

    Returns:
        Configured CodeIngestorToolkit instance
    """
    # Build the data dict for the model validator
    data = {
        "parent_path": parent_path,
        "max_file_size": max_file_size,
    }

    # Only add exclude_patterns if it's not None
    if exclude_patterns is not None:
        data["exclude_patterns"] = exclude_patterns

    return CodeIngestorToolkit(**data)
