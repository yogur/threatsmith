## OWASP API Security Top 10 (2023)

Use the following as an additional coverage checklist for API-related threats:

- **API1: Broken Object Level Authorization** — API endpoints expose object IDs without proper authorization checks
- **API2: Broken Authentication** — authentication endpoints improperly protected against credential stuffing and brute force
- **API3: Broken Object Property Level Authorization** — API exposes or allows modification of object properties users shouldn't access
- **API4: Unrestricted Resource Consumption** — missing limits on API resource usage leading to DoS or excessive cost
- **API5: Broken Function Level Authorization** — insufficient checks allowing access to functions beyond user privilege level
- **API6: Unrestricted Access to Sensitive Business Flows** — no protection against automated abuse of sensitive business operations
- **API7: Server Side Request Forgery** — API fetches remote resources without validating user-supplied URLs
- **API8: Security Misconfiguration** — improper security configuration across any part of the API stack
- **API9: Improper Inventory Management** — lack of visibility and management of API endpoints and data flows
- **API10: Unsafe Consumption of APIs** — insufficient validation when consuming third-party API data
