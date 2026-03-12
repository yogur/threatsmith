OWASP_WEB_TOP_10 = """
Use the following OWASP Top 10 (2025) as a coverage checklist to ensure your threat analysis addresses these established patterns where relevant:

A01: Broken Access Control — users acting outside intended permissions through missing, weak, or bypassed authorization controls
A02: Security Misconfiguration — insecure defaults, unnecessary features enabled, weak settings, missing security hardening, or disabled security features
A03: Software Supply Chain Failures — vulnerabilities or compromises in third-party code, tools, dependencies, and supply chain processes
A04: Cryptographic Failures — weak or missing encryption, deprecated algorithms, poor key management, or unencrypted sensitive data
A05: Injection — user-supplied data not validated, filtered, or sanitized before being passed to an interpreter as commands
A06: Insecure Design — missing or ineffective security controls in application design
A07: Authentication Failures — weak authentication controls allowing credential attacks, brute force, weak passwords, or session hijacking
A08: Software and Data Integrity Failures — treating untrusted code, plugins, libraries, or data as trusted without integrity verification
A09: Security Logging and Alerting Failures — insufficient logging, monitoring, detection, or alerting preventing timely incident response
A10: Mishandling of Exceptional Conditions — failure to prevent, detect, and respond to exceptional conditions leaving applications in unpredictable states
"""

OWASP_API_TOP_10 = """
Use the following OWASP API Security Top 10 (2023) as an additional coverage checklist for API-related threats:

API1: Broken Object Level Authorization — API endpoints expose object IDs without proper authorization checks
API2: Broken Authentication — authentication endpoints improperly protected against credential stuffing and brute force
API3: Broken Object Property Level Authorization — API exposes or allows modification of object properties users shouldn't access
API4: Unrestricted Resource Consumption — missing limits on API resource usage leading to DoS or excessive cost
API5: Broken Function Level Authorization — insufficient checks allowing access to functions beyond user privilege level
API6: Unrestricted Access to Sensitive Business Flows — no protection against automated abuse of sensitive business operations
API7: Server Side Request Forgery — API fetches remote resources without validating user-supplied URLs
API8: Security Misconfiguration — improper security configuration across any part of the API stack
API9: Improper Inventory Management — lack of visibility and management of API endpoints and data flows
API10: Unsafe Consumption of APIs — insufficient validation when consuming third-party API data
"""

OWASP_LLM_TOP_10 = """
Use the following OWASP LLM Top 10 (2025) as an additional coverage checklist for LLM/AI-related threats:

LLM01: Prompt Injection — user prompts alter LLM behavior in unintended ways bypassing guidelines
LLM02: Sensitive Information Disclosure — LLM exposes PII, credentials, or proprietary data in responses
LLM03: Supply Chain — vulnerabilities in training data, models, or deployment platform dependencies
LLM04: Data and Model Poisoning — manipulation of training data introducing vulnerabilities or biases
LLM05: Improper Output Handling — insufficient validation of LLM outputs before passing to downstream systems
LLM06: Excessive Agency — LLM granted excessive functionality, permissions, or autonomy enabling harmful actions
LLM07: System Prompt Leakage — system prompts containing credentials or sensitive instructions are disclosed
LLM08: Vector and Embedding Weaknesses — RAG system vulnerabilities enabling content injection or data leakage
LLM09: Misinformation — LLM produces false or misleading content that appears credible
LLM10: Unbounded Consumption — uncontrolled LLM inference leading to DoS, excessive cost, or model theft
"""

OWASP_MOBILE_TOP_10 = """
Use the following OWASP Top 10 Mobile (2023) as an additional coverage checklist for mobile-specific threats:

M1: Improper Credential Usage — hardcoded or improperly managed credentials enabling unauthorized access
M2: Inadequate Supply Chain Security — compromised third-party components and malicious code injection during development
M3: Insecure Authentication/Authorization — weak authentication mechanisms and missing authorization checks enabling unauthorized actions
M4: Insufficient Input/Output Validation — inadequate input sanitization and output encoding leading to injection attacks
M5: Insecure Communication — inadequate encryption and weak TLS configuration enabling eavesdropping and MITM attacks
M6: Inadequate Privacy Controls — insufficient PII protection and improper data handling exposing sensitive information
M7: Insufficient Binary Protection — lack of reverse engineering and tampering protections exposing sensitive logic and credentials
M8: Security Misconfiguration — improper security configuration including default settings, excessive permissions, and exposed components
M9: Insecure Data Storage — inadequate protection of sensitive data stored locally on mobile devices through weak encryption and access controls
M10: Insufficient Cryptography — weak cryptographic algorithms, improper key management, and flawed encryption implementation
"""
