"""
Reporting utilities for ThreatSmith analysis results.

Provides flexible reporting options:
- Simple mode: Only saves the final report
- Stage outputs mode: Optionally saves a second markdown with raw outputs from each stage
"""

from datetime import datetime
from pathlib import Path
from typing import Dict

from threatsmith.utils.logging import get_logger


class ThreatAnalysisReporter:
    """
    Handles saving threat analysis results in different formats.

    Modes:
    - Simple: Saves only the final_report to a clean markdown file
    - Stage outputs: Additionally saves a markdown with raw outputs from all stages
    """

    def __init__(self, output_dir: Path):
        """
        Initialize the reporter.

        Args:
            output_dir: Directory where reports will be saved
        """
        self.output_dir = Path(output_dir)
        self.logger = get_logger(__name__)

    def save_results(
        self,
        state: Dict,
        save_stage_outputs: bool = False,
        html_output: bool = True,
    ) -> Dict[str, str]:
        """
        Save analysis results.

        Args:
            state: The analysis state containing all agent outputs
            save_stage_outputs: If True, save an additional markdown with raw outputs from each stage
            html_output: If True, save final report as HTML

        Returns:
            Dictionary with paths of saved files
        """
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

        saved_files = {}

        # Generate formatted markdown content once
        final_report = state.get("final_report", "")
        if not final_report:
            self.logger.warning("No final report found in state")
            final_report = "# Threat Analysis Report\n\n*No final report generated*"

        formatted_final_markdown = self._format_final_report_markdown(
            final_report, state
        )

        # Always save the final report
        final_report_path = self._save_final_report(formatted_final_markdown)
        saved_files["final_report"] = final_report_path
        self.logger.info(f"Final report saved: {final_report_path}")

        # Save stage outputs markdown if enabled
        if save_stage_outputs:
            stage_outputs_path = self._save_stage_outputs(state)
            saved_files["stage_outputs"] = stage_outputs_path
            self.logger.info(f"Stage outputs saved: {stage_outputs_path}")

        # Save HTML version if requested
        if html_output:
            html_report_path = self._save_final_report_html(formatted_final_markdown)
            saved_files["html_report"] = html_report_path
            self.logger.info(f"HTML report saved: {html_report_path}")

        return saved_files

    def _save_final_report(self, formatted_markdown: str) -> str:
        """
        Save formatted markdown to file.

        Args:
            formatted_markdown: Pre-formatted markdown content

        Returns:
            Path to the saved file
        """
        # Create clean filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_analysis_report_{timestamp}.md"
        filepath = self.output_dir / filename

        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(formatted_markdown)

        return str(filepath.absolute())

    def _save_stage_outputs(self, state: Dict) -> str:
        """
        Save raw outputs from all analysis stages.

        Args:
            state: The analysis state

        Returns:
            Path to the saved file
        """
        # Create filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_analysis_stage_outputs_{timestamp}.md"
        filepath = self.output_dir / filename

        # Create content
        content = self._format_stage_outputs_markdown(state)

        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        return str(filepath.absolute())

    def _format_final_report_markdown(self, final_report: str, state: Dict) -> str:
        """
        Format the final report with minimal header information.

        Args:
            final_report: The final report content
            state: The analysis state for metadata

        Returns:
            Formatted markdown content
        """
        lines = []

        # Add header
        lines.append("# Threat Analysis Report")
        lines.append("")
        lines.append(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        lines.append("")

        # Add target information if available
        target_path = state.get("target_path")
        if target_path:
            lines.append(f"**Target:** {target_path}")
            lines.append("")

        # Add business/security objectives if provided
        business_obj = state.get("business_objectives")
        security_obj = state.get("security_objectives")

        if business_obj or security_obj:
            lines.append("## Analysis Objectives")
            lines.append("")

            if business_obj:
                lines.append(f"**Business Objectives:** {business_obj}")
                lines.append("")

            if security_obj:
                lines.append(f"**Security Objectives:** {security_obj}")
                lines.append("")

        # Add separator
        lines.append("---")
        lines.append("")

        # Add the final report content
        lines.append(final_report)

        return "\n".join(lines)

    def _format_stage_outputs_markdown(self, state: Dict) -> str:
        """
        Format a markdown document that captures raw outputs from all analysis stages.

        Args:
            state: The analysis state

        Returns:
            Formatted markdown content
        """
        lines = []

        # Add title and timestamp
        lines.append("# Threat Analysis - Stage Outputs")
        lines.append("")
        lines.append(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        lines.append("")

        # Add target information
        target_path = state.get("target_path")
        if target_path:
            lines.append(f"**Target:** {target_path}")
            lines.append("")

        # Add initial parameters if provided
        self._add_initial_parameters(lines, state)

        # Add each analysis stage raw outputs
        self._add_analysis_stages(lines, state)

        return "\n".join(lines)

    def _add_initial_parameters(self, lines: list, state: Dict) -> None:
        """Add initial parameters section if any are provided."""
        business_obj = state.get("business_objectives")
        security_obj = state.get("security_objectives")

        if business_obj or security_obj:
            lines.append("## Analysis Parameters")
            lines.append("")

            if business_obj:
                lines.append("### Business Objectives")
                lines.append("")
                lines.append(business_obj)
                lines.append("")

            if security_obj:
                lines.append("### Security Objectives")
                lines.append("")
                lines.append(security_obj)
                lines.append("")

    def _add_analysis_stages(self, lines: list, state: Dict) -> None:
        """Add all analysis stages with proper headers."""
        # Define analysis stages in order with their display names
        analysis_stages = [
            ("objectives_analysis", "Stage 1: Objectives Analysis"),
            ("technical_scope", "Stage 2: Technical Scope"),
            ("application_decomposition", "Stage 3: Application Decomposition"),
            ("threat_analysis", "Stage 4: Threat Analysis"),
            ("vulnerability_analysis", "Stage 5: Vulnerability Analysis"),
            ("attack_modeling", "Stage 6: Attack Modeling"),
            ("final_report", "Stage 7: Final Report"),
        ]

        for field_name, display_name in analysis_stages:
            output_data = state.get(field_name, "")

            if output_data:  # Only add sections that have content
                lines.append(f"## {display_name}")
                lines.append("")
                lines.append(str(output_data))
                lines.append("")

    def _save_final_report_html(self, formatted_markdown: str) -> str:
        """
        Save final report as HTML with embedded markdown rendering.

        Args:
            formatted_markdown: Pre-formatted markdown content

        Returns:
            Path to the saved HTML file
        """
        # Escape backtick characters in the markdown content
        escaped_markdown = formatted_markdown.replace("`", "\\`")

        # Create filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_analysis_report_{timestamp}.html"
        filepath = self.output_dir / filename

        # HTML template with embedded marked.js
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ThreatSmith Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/dompurify@3/dist/purify.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/marked@16/lib/marked.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }}
        #content {{ margin-top: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        code {{ background-color: #f8f9fa; padding: 2px 4px; border-radius: 4px; }}
        pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 4px; overflow: auto; }}
        blockquote {{ border-left: 4px solid #ddd; padding-left: 15px; color: #666; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div id="content"></div>
    <script>
        mermaid.initialize({{startOnLoad: false}});

        marked.use({{
            renderer: {{
                code(token) {{
                    if (token.lang === 'mermaid') {{
                        return '<pre class="mermaid">' + token.text + '</pre>';
                    }}
                    // Return false to use default renderer for other code blocks
                    return false;
                }}
            }}
        }})

        const markdownContent = `{escaped_markdown}`;
        document.getElementById('content').innerHTML = DOMPurify.sanitize(marked.parse(markdownContent));
        mermaid.run();
    </script>
</body>
</html>
        """

        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(filepath.absolute())
