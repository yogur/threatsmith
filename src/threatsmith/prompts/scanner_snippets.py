SEMGREP_SNIPPET = """
Semgrep is available on this system. Run it against the codebase to augment your analysis.
Use the severity filter to limit results to high-signal findings and reduce noise.
Example: semgrep scan --config auto --severity=ERROR --json --quiet --no-error <target_path>
Integrate the JSON results into your vulnerability assessment.
"""

TRIVY_SNIPPET = """
Trivy is available on this system. Run it to scan for dependency CVEs.
Use the severity and scanners filters to focus on critical/high vulnerabilities only and reduce noise.
Example: trivy fs --format json --severity CRITICAL,HIGH --scanners vuln --quiet --exit-code 0 <target_path>
Integrate the JSON results into your vulnerability assessment.
"""

GITLEAKS_SNIPPET = """
Gitleaks is available on this system. Run it to detect secrets and credentials in the codebase.
Use the redact flag to avoid surfacing raw secret values in the report.
Example: gitleaks dir --report-format json --report-path gitleaks-report.json --no-banner --redact=100 <target_path>
Integrate any detected secrets into your vulnerability assessment.
"""

SCANNER_SNIPPETS = {
    "semgrep": SEMGREP_SNIPPET,
    "trivy": TRIVY_SNIPPET,
    "gitleaks": GITLEAKS_SNIPPET,
}
