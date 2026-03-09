# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in agent-tool-firewall, please report it responsibly:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/SecAI-Hub/agent-tool-firewall/security/advisories/new)
2. **Email:** Open a GitHub Security Advisory (no public email for now).

**Do not** open a public GitHub issue for security vulnerabilities.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgement | 48 hours |
| Triage and severity assessment | 5 business days |
| Fix for Critical | 7 days |
| Fix for High | 30 days |
| Fix for Medium/Low | 90 days |

## Disclosure expectations

- **Acknowledgement:** You will receive an acknowledgement within **48 hours** of your report confirming receipt.
- **Critical fixes:** Critical severity vulnerabilities (e.g., policy bypass, authentication bypass) will be patched within **7 days** of confirmation.
- **Coordinated disclosure:** We follow coordinated disclosure. We ask reporters to avoid public disclosure until a fix is available and a reasonable disclosure window (typically 90 days) has passed.
- **Credit:** Security researchers will be credited in the release notes and CHANGELOG unless they request anonymity.

## Scope

### In scope

- Policy evaluation logic (allow/deny, path matching, argument validation)
- Rate limiting bypass
- Path traversal or null-byte injection bypass
- Authentication bypass on `/v1/reload`
- Audit log injection or tampering
- Denial of service via crafted requests

### Out of scope

- Vulnerabilities in Go standard library or `gopkg.in/yaml.v3`
- Issues in container base images (Alpine, Go)
- Deployment misconfigurations (running as root, exposing to public network)

## Supported versions

| Version | Supported |
|---|---|
| latest `main` | Yes — security fixes |
| v0.1.x | Yes — security fixes |
| < v0.1.0 | No |

Only the latest release on the `main` branch receives security fixes.
Pre-release builds and older tags are not supported.
