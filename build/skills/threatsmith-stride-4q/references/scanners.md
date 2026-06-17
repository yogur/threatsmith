## Security Scanner Usage

Detect which of the following tools are available on this system (e.g., via `which semgrep`, `which trivy`, `which gitleaks`) and run the ones that are present. Integrate all results into your vulnerability assessment.

### Semgrep — Static Analysis

Run against the codebase to identify code-level vulnerabilities. Use the severity filter to limit results to high-signal findings and reduce noise.

```
semgrep scan --config auto --severity=ERROR --json --quiet --no-error <target_path>
```

### Trivy — Dependency CVE Scanning

Run to scan for known CVEs in dependencies. Focus on critical and high severity only to reduce noise.

```
trivy fs --format json --severity CRITICAL,HIGH --scanners vuln --quiet --exit-code 0 <target_path>
```

### Gitleaks — Secret Detection

Run to detect secrets and credentials in the codebase. Use the redact flag to avoid surfacing raw secret values in the report.

```
gitleaks dir --report-format json --report-path gitleaks-report.json --no-banner --redact=100 <target_path>
```
