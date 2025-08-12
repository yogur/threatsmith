import asyncio
from pathlib import Path
from typing import Optional

from playwright.async_api import async_playwright


class PlaywrightMermaidRenderer:
    """
    A utility class for rendering Mermaid diagrams using Playwright.

    This class provides methods to render Mermaid diagram syntax into PNG images
    using a headless browser with Playwright.
    """

    def __init__(
        self,
        background_color: str = "white",
        padding: int = 10,
        device_scale_factor: int = 3,
        timeout: int = 10000,
    ):
        """
        Initialize the renderer with configuration options.

        Args:
            background_color: Background color for the rendered diagram
            padding: Padding around the diagram in pixels
            device_scale_factor: Scale factor for high-resolution rendering
            timeout: Timeout for browser operations in milliseconds
        """
        self.background_color = background_color
        self.padding = padding
        self.device_scale_factor = device_scale_factor
        self.timeout = timeout

    async def render_mermaid_to_png(
        self,
        mermaid_syntax: str,
        output_file_path: Optional[str] = None,
        background_color: Optional[str] = None,
        padding: Optional[int] = None,
    ) -> bytes:
        """
        Render a Mermaid diagram to PNG format using Playwright.

        Args:
            mermaid_syntax: The Mermaid diagram syntax to render
            output_file_path: Optional file path to save the PNG. If None, returns bytes only
            background_color: Override background color for this render
            padding: Override padding for this render

        Returns:
            PNG image as bytes

        Raises:
            ImportError: If playwright is not installed
            Exception: If rendering fails
        """
        try:
            async with async_playwright() as p:
                # Launch browser in headless mode
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()

                # Setup Mermaid JS
                await page.goto("about:blank", wait_until="networkidle")
                await page.add_script_tag(
                    url="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"
                )

                # Initialize Mermaid
                await page.evaluate(
                    """() => {
                        mermaid.initialize({
                            startOnLoad: true,
                            theme: 'default',
                            securityLevel: 'loose'
                        });
                    }"""
                )

                # Render SVG from Mermaid syntax
                svg_result = await page.evaluate(
                    """async (mermaidGraph) => {
                        try {
                            const { svg } = await mermaid.render('mermaid', mermaidGraph);
                            return { success: true, svg: svg };
                        } catch (error) {
                            return { success: false, error: error.message };
                        }
                    }""",
                    mermaid_syntax,
                )

                if not svg_result.get("success"):
                    raise ValueError(
                        f"Mermaid rendering failed: {svg_result.get('error', 'Unknown error')}"
                    )

                # Use provided parameters or fall back to instance defaults
                bg_color = background_color or self.background_color
                pad = padding if padding is not None else self.padding

                # Set the page content with the SVG and background
                await page.evaluate(
                    """(params) => {
                        document.body.innerHTML = params.svg;
                        document.body.style.background = params.background_color;
                        document.body.style.margin = '0';
                        document.body.style.padding = '0';
                    }""",
                    {"svg": svg_result["svg"], "background_color": bg_color},
                )

                # Get SVG dimensions for proper viewport sizing
                dimensions = await page.evaluate(
                    """() => {
                        const svgElement = document.querySelector('svg');
                        if (!svgElement) {
                            return { width: 800, height: 600 };
                        }
                        const rect = svgElement.getBoundingClientRect();
                        return { width: rect.width, height: rect.height };
                    }"""
                )

                # Set viewport size based on SVG dimensions plus padding
                await page.set_viewport_size(
                    {
                        "width": int(dimensions["width"] + pad * 2),
                        "height": int(dimensions["height"] + pad * 2),
                    }
                )

                # Take screenshot
                img_bytes = await page.screenshot(
                    full_page=False,
                    timeout=self.timeout,
                    type="png",
                )

                await browser.close()

                # Save to file if path provided
                if output_file_path is not None:
                    Path(output_file_path).write_bytes(img_bytes)

                return img_bytes

        except ImportError as e:
            msg = (
                "Playwright is not installed. Please install it using: "
                "`pip install playwright` and then run `playwright install`"
            )
            raise ImportError(msg) from e
        except Exception as e:
            raise Exception(f"Failed to render Mermaid diagram: {str(e)}") from e

    def render_mermaid_to_png_sync(
        self,
        mermaid_syntax: str,
        output_file_path: Optional[str] = None,
        background_color: Optional[str] = None,
        padding: Optional[int] = None,
    ) -> bytes:
        """
        Synchronous wrapper for render_mermaid_to_png.

        Args:
            mermaid_syntax: The Mermaid diagram syntax to render
            output_file_path: Optional file path to save the PNG
            background_color: Override background color for this render
            padding: Override padding for this render

        Returns:
            PNG image as bytes
        """
        return asyncio.run(
            self.render_mermaid_to_png(
                mermaid_syntax, output_file_path, background_color, padding
            )
        )

    async def validate_mermaid_syntax(self, mermaid_syntax: str) -> tuple[bool, str]:
        """
        Validate Mermaid syntax by attempting to render it.

        Args:
            mermaid_syntax: The Mermaid diagram syntax to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            await self.render_mermaid_to_png(mermaid_syntax)
            return True, "Syntax is valid"
        except Exception as e:
            return False, str(e)

    def validate_mermaid_syntax_sync(self, mermaid_syntax: str) -> tuple[bool, str]:
        """
        Synchronous wrapper for validate_mermaid_syntax.

        Args:
            mermaid_syntax: The Mermaid diagram syntax to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        return asyncio.run(self.validate_mermaid_syntax(mermaid_syntax))
