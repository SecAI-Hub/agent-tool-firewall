# Threat Model

## Overview

agent-tool-firewall is a default-deny policy gateway that sits between an LLM/AI agent and the backend tools it invokes. This document describes trust boundaries, known threats, existing mitigations, and residual risks.

## Trust boundaries

```
+-------------------+        +-----------------------+        +---------------+
|   LLM / Agent     | -----> |  agent-tool-firewall  | -----> |  Backend Tool |
|   (untrusted)     |  HTTP  |  (trust boundary)     |        |  (trusted)    |
+-------------------+        +-----------------------+        +---------------+
                                      |
                                      v
                               Audit log (JSONL)
```

| Boundary | From | To | Trust level |
|---|---|---|---|
| B1: Agent -> Firewall | LLM agent | Firewall `/v1/evaluate` | Untrusted. The agent may be prompt-injected or compromised. All input is treated as adversarial. |
| B2: Firewall -> Backend | Firewall decision | Backend tool execution | Trusted. The firewall's allow decision is authoritative. The backend tool trusts that the firewall has validated the call. |
| B3: Admin -> Firewall | Operator | `/v1/reload` endpoint | Privileged. Protected by bearer token authentication. Policy changes affect the entire security posture. |
| B4: Firewall -> Audit log | Firewall | Audit log file | Trusted output. The audit log must not be writable by the agent or backend tools. |

## Threats

### T1: Policy bypass

**Description:** An attacker crafts a tool call that circumvents policy evaluation, gaining access to a denied or unlisted tool.

**Attack vectors:**
- Tool name manipulation (case variations, Unicode confusables)
- Exploiting gaps between policy evaluation and actual tool invocation

**Severity:** Critical

### T2: Path traversal

**Description:** An attacker uses directory traversal sequences to escape the allowlisted directories and access sensitive files.

**Attack vectors:**
- `../../etc/shadow` style relative path escapes
- Null-byte injection (`file.txt\x00.jpg`)
- Symlink following to escape the allowlist jail
- URL-encoded path components (`%2e%2e%2f`)
- Unicode normalization tricks (fullwidth characters, combining dots)

**Severity:** Critical

### T3: Argument injection

**Description:** An attacker injects malicious content into tool arguments to exploit downstream tools.

**Attack vectors:**
- Shell metacharacters in arguments passed to shell-based tools
- Oversized arguments to trigger buffer overflows in downstream consumers
- Blocklisted patterns hidden via encoding or case manipulation

**Severity:** High

### T4: Token exfiltration

**Description:** An attacker extracts the service bearer token used for the `/v1/reload` endpoint, enabling unauthorized policy changes.

**Attack vectors:**
- Reading the token file via a path traversal in a filesystem tool
- Exfiltrating the token from process environment or memory
- Sniffing the token on the network (if not using TLS)

**Severity:** High

### T5: Denial of service via rate limit abuse

**Description:** An attacker floods the firewall with requests to exhaust the rate limit budget, blocking legitimate tool calls.

**Attack vectors:**
- Rapid-fire requests to consume the sliding window budget
- Distributed requests from multiple compromised agents
- Oversized request bodies to consume memory/CPU

**Severity:** Medium

## Mitigations in place

| Threat | Mitigation | Implementation |
|---|---|---|
| T1: Policy bypass | Default-deny policy | Tools must be explicitly listed in the allow list. Unknown tools are rejected. Deny list is evaluated before allow list. |
| T2: Path traversal | Path canonicalization and validation | `filepath.Clean` + `filepath.Abs` resolve all `../` sequences. Null bytes are rejected. Paths are matched against allowlist/denylist after canonicalization. |
| T3: Argument injection | Argument filtering and length limits | `max_arg_length` enforces size limits. `args_blocklist` rejects arguments containing dangerous patterns. Case-insensitive matching. |
| T4: Token exfiltration | Bearer token auth with constant-time comparison | Token loaded from a file (not environment variable). `crypto/subtle.ConstantTimeCompare` prevents timing attacks. Token file should be root-owned with mode 0400. |
| T5: DoS via rate limiting | Sliding window rate limiter | Configurable `requests_per_minute` with burst support. Request body size capped at 64 KB via `http.MaxBytesReader`. |
| General | Minimal attack surface | Single static binary with zero runtime dependencies. No shell access. No network egress. Systemd sandboxing (DynamicUser, PrivateNetwork, seccomp). |
| General | Audit logging | Every policy decision is logged to a structured JSONL audit trail with timestamp, tool name, parameters, decision, and reason. |

## Residual risks

| Risk | Description | Recommended mitigation |
|---|---|---|
| R1: Symlink race conditions | `filepath.Clean`/`filepath.Abs` do not resolve symlinks. A symlink within an allowlisted directory could point outside it. | Mount allowlisted directories with `nosymfollow` or use `filepath.EvalSymlinks` (adds a stat syscall per request). |
| R2: Unicode normalization | Fullwidth Unicode characters (e.g., `\uff0e\uff0e/` as `../`) are not normalized before path matching. | Add Unicode NFKC normalization before path validation. |
| R3: TOCTOU on policy reload | A race between reading the policy file and applying it could lead to inconsistent state. | The current `sync.RWMutex` serializes reads and writes, but file-level TOCTOU remains if the file is modified during read. Use atomic file replacement (rename). |
| R4: No TLS by default | The firewall listens on plain HTTP. If exposed beyond localhost, tokens and tool call data are transmitted in cleartext. | Default bind is `127.0.0.1` (localhost only). For multi-host deployments, use a reverse proxy with mTLS termination. |
| R5: Single-point rate limiter | The rate limiter is in-process and per-instance. Multiple firewall instances do not share rate limit state. | Acceptable for single-appliance deployment. For distributed deployments, use an external rate limiter (e.g., envoy, nginx). |
| R6: No request authentication on /v1/evaluate | Any process on localhost can submit tool evaluation requests. | Acceptable for appliance mode where only the trusted agent process has access. For multi-tenant deployments, add per-client authentication. |
