# Security policy

DEVIL is a research/prototype defensive intelligence dashboard. It is **not independently audited** and is not a security boundary on its own.

Please do not open public GitHub issues containing credential strings, infrastructure addresses, customer IP lists, access logs, malware samples, personal information or exploit details. Report security problems **privately** to the repository maintainer through GitHub's private vulnerability reporting if available.

Supported branch: the latest reviewed 3.1.x source. Fixes may be prioritized based on reproducibility and severity; no formal SLA is promised.

**Deployment rule:** Never expose port 8765 directly to untrusted networks. Enforce authentication, TLS and authorization at a trusted reverse proxy. Prefer MFA and private access for sensitive operations.
