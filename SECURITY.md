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
| Triage and severity assessment | 7 days |
| Fix for Critical/High | 90 days |

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

Only the latest release on the `main` branch is supported with security fixes.
