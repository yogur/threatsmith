from typing import List, Annotated, Optional, Any
import base64

from langchain_core.tools import BaseTool, tool
from langchain_core.tools.base import BaseToolkit
from pydantic import Field

from threatsmith.utils.logging import get_logger
from threatsmith.utils.mermaid_renderer import PlaywrightMermaidRenderer


class MermaidDiagrammingToolkit(BaseToolkit):
    """
    A LangChain toolkit for Mermaid diagram creation and validation using Playwright.

    This toolkit provides two tools for working with Mermaid diagrams:
    - validate_mermaid_syntax: Validate Mermaid diagram syntax without rendering
    - render_mermaid_diagram: Render Mermaid diagrams to PNG format

    The toolkit is optimized for LLM agents to create data flow diagrams (DFDs),
    sequence diagrams, and other Mermaid-supported diagram types.
    """

    background_color: str = Field(
        default="white", description="Background color for rendered diagrams"
    )
    padding: int = Field(
        default=10, description="Padding around the rendered diagram in pixels"
    )
    device_scale_factor: int = Field(
        default=3, description="Scale factor for high-resolution rendering"
    )
    timeout: int = Field(
        default=10000, description="Timeout for browser operations in milliseconds"
    )
    max_retries: int = Field(
        default=3, description="Maximum number of retries for diagram rendering"
    )
    retry_delay: float = Field(
        default=1.0, description="Delay between retries in seconds"
    )

    logger: Any = Field(
        default_factory=lambda: get_logger("mermaid_diagramming"),
        description="Logger instance for this toolkit",
    )

    def get_tools(self) -> List[BaseTool]:
        """Return the list of tools in this toolkit."""
        return [
            self._create_validation_tool(),
            self._create_rendering_tool(),
        ]

    def _get_renderer(self) -> PlaywrightMermaidRenderer:
        """Create a configured PlaywrightMermaidRenderer instance."""
        return PlaywrightMermaidRenderer(
            background_color=self.background_color,
            padding=self.padding,
            device_scale_factor=self.device_scale_factor,
            timeout=self.timeout,
        )

    def _create_validation_tool(self) -> BaseTool:
        """Create the Mermaid syntax validation tool."""

        @tool
        def validate_mermaid_syntax(
            mermaid_syntax: Annotated[
                str,
                "The Mermaid diagram syntax to validate. Can be any valid Mermaid diagram type (flowchart, sequence, etc.)",
            ],
        ) -> str:
            """
            Validate Mermaid diagram syntax without rendering the actual diagram.

            This tool checks if the provided Mermaid syntax is valid and can be rendered.
            It's useful for LLM agents to verify their generated diagram syntax before
            attempting to render, especially for complex data flow diagrams (DFDs) or
            sequence diagrams.

            Returns a validation result indicating success or failure with error details.
            """
            self.logger.debug(
                "validate_mermaid_syntax called", syntax_length=len(mermaid_syntax)
            )

            renderer = self._get_renderer()

            try:
                is_valid, error_message = renderer.validate_mermaid_syntax_sync(
                    mermaid_syntax
                )
                if is_valid:
                    result = (
                        "✅ Mermaid syntax is valid and can be rendered successfully."
                    )
                    self.logger.debug(
                        "validate_mermaid_syntax returning success",
                        syntax_length=len(mermaid_syntax),
                    )
                    return result
                else:
                    # Wrap third-party error in XML-like tag for clearer parsing by agents
                    result = (
                        "❌ Mermaid syntax validation failed: "
                        f"<error_message>{error_message}</error_message>"
                    )
                    self.logger.debug(
                        "validate_mermaid_syntax validation failed",
                        syntax_length=len(mermaid_syntax),
                        error=error_message,
                    )
                    return result
            except Exception as e:
                result = (
                    "❌ Mermaid syntax validation failed: "
                    f"<error_message>{str(e)}</error_message>"
                )
                self.logger.error(
                    "Error in validate_mermaid_syntax",
                    syntax_length=len(mermaid_syntax),
                    error=str(e),
                )
                return result

        return validate_mermaid_syntax

    def _create_rendering_tool(self) -> BaseTool:
        """Create the Mermaid diagram rendering tool."""

        @tool
        def render_mermaid_diagram(
            mermaid_syntax: Annotated[
                str, "The Mermaid diagram syntax to render as PNG"
            ],
            output_file_path: Annotated[
                Optional[str],
                "Optional file path to save the PNG. If None, returns base64-encoded PNG data",
            ] = None,
            background_color: Annotated[
                Optional[str],
                "Background color for the diagram (overrides toolkit default if provided)",
            ] = None,
            padding: Annotated[
                Optional[int],
                "Padding around the diagram in pixels (overrides toolkit default if provided)",
            ] = None,
        ) -> str:
            """
            Render a Mermaid diagram to PNG format using Playwright.

            This tool takes valid Mermaid syntax and renders it as a PNG image.
            It can either save the image to a file or return it as base64-encoded data
            for immediate use.

            Supports all Mermaid diagram types including:
            - Flowcharts and data flow diagrams (DFDs)
            - Sequence diagrams
            - Class diagrams
            - State diagrams
            - And more

            Returns either a success message with file path or base64-encoded PNG data.
            """
            self.logger.debug(
                "render_mermaid_diagram called",
                syntax_length=len(mermaid_syntax),
                output_file_path=output_file_path,
                background_color=background_color,
                padding=padding,
            )

            renderer = self._get_renderer()

            try:
                # Implement retry logic
                last_exception = None
                for attempt in range(self.max_retries + 1):
                    try:
                        result = renderer.render_mermaid_to_png_sync(
                            mermaid_syntax=mermaid_syntax,
                            output_file_path=output_file_path,
                            background_color=background_color,
                            padding=padding,
                        )

                        if output_file_path:
                            success_msg = f"✅ Mermaid diagram successfully rendered and saved to: {output_file_path}"
                            self.logger.debug(
                                "render_mermaid_diagram success - file saved",
                                output_file_path=output_file_path,
                                attempt=attempt + 1,
                            )
                            return success_msg
                        else:
                            # Result is bytes, encode as base64 for text return
                            base64_data = base64.b64encode(result).decode("utf-8")
                            success_msg = f"✅ Mermaid diagram rendered successfully. Base64 PNG data:\n{base64_data}"
                            self.logger.debug(
                                "render_mermaid_diagram success - base64 returned",
                                base64_length=len(base64_data),
                                attempt=attempt + 1,
                            )
                            return success_msg

                    except Exception as e:
                        last_exception = e
                        if attempt < self.max_retries:
                            # Wait before retrying
                            import time

                            self.logger.debug(
                                "render_mermaid_diagram retry",
                                attempt=attempt + 1,
                                max_retries=self.max_retries,
                                error=str(e),
                            )
                            time.sleep(self.retry_delay * (attempt + 1))
                            continue
                        else:
                            break

                # If we reach here, all retries failed
                error_msg = f"❌ Failed to render Mermaid diagram after {self.max_retries + 1} attempts: {str(last_exception)}"
                self.logger.error(
                    "render_mermaid_diagram failed after all retries",
                    max_retries=self.max_retries + 1,
                    final_error=str(last_exception),
                )
                return error_msg

            except Exception as e:
                error_msg = f"❌ Failed to render Mermaid diagram: {str(e)}"
                self.logger.error(
                    "render_mermaid_diagram unexpected error", error=str(e)
                )
                return error_msg

        return render_mermaid_diagram


# Individual tool creation functions for separate usage
def create_mermaid_validation_tool(
    background_color: str = "white",
    padding: int = 10,
    device_scale_factor: int = 3,
    timeout: int = 10000,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> BaseTool:
    """
    Create a standalone Mermaid syntax validation tool using Playwright.

    Args:
        background_color: Background color for validation rendering
        padding: Padding around the diagram in pixels
        device_scale_factor: Scale factor for high-resolution rendering
        timeout: Timeout for browser operations in milliseconds
        max_retries: Maximum number of retries for validation
        retry_delay: Delay between retries in seconds

    Returns:
        BaseTool: The validation tool
    """
    toolkit = MermaidDiagrammingToolkit(
        background_color=background_color,
        padding=padding,
        device_scale_factor=device_scale_factor,
        timeout=timeout,
        max_retries=max_retries,
        retry_delay=retry_delay,
    )
    return toolkit._create_validation_tool()


def create_mermaid_rendering_tool(
    background_color: str = "white",
    padding: int = 10,
    device_scale_factor: int = 3,
    timeout: int = 10000,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> BaseTool:
    """
    Create a standalone Mermaid diagram rendering tool using Playwright.

    Args:
        background_color: Background color for rendered diagrams
        padding: Padding around the diagram in pixels
        device_scale_factor: Scale factor for high-resolution rendering
        timeout: Timeout for browser operations in milliseconds
        max_retries: Maximum number of retries for rendering
        retry_delay: Delay between retries in seconds

    Returns:
        BaseTool: The rendering tool
    """
    toolkit = MermaidDiagrammingToolkit(
        background_color=background_color,
        padding=padding,
        device_scale_factor=device_scale_factor,
        timeout=timeout,
        max_retries=max_retries,
        retry_delay=retry_delay,
    )
    return toolkit._create_rendering_tool()


# Convenience function for quick toolkit creation
def create_mermaid_diagramming_toolkit(
    background_color: str = "white",
    padding: int = 10,
    device_scale_factor: int = 3,
    timeout: int = 10000,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> MermaidDiagrammingToolkit:
    """
    Create a MermaidDiagramming toolkit with the specified configuration.

    This version uses Playwright instead of the deprecated pyppeteer for better
    reliability and maintenance.

    Args:
        background_color: Background color for rendered diagrams
        padding: Padding around the diagram in pixels
        device_scale_factor: Scale factor for high-resolution rendering
        timeout: Timeout for browser operations in milliseconds
        max_retries: Maximum number of retries for rendering
        retry_delay: Delay between retries in seconds

    Returns:
        Configured MermaidDiagrammingToolkit instance
    """
    return MermaidDiagrammingToolkit(
        background_color=background_color,
        padding=padding,
        device_scale_factor=device_scale_factor,
        timeout=timeout,
        max_retries=max_retries,
        retry_delay=retry_delay,
    )
