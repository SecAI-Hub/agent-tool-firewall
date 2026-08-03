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
| B3: Admin -> Firewall | Operator | `/v1/reload` endpoint | Privileged. Requires an isolated administrator identity that cannot evaluate or observe. Policy changes affect the entire security posture. |
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

**Description:** An attacker extracts a bearer token. Its effect is limited to the exact roles bound to that credential identity, but evaluator access can still authorize unsafe calls.

**Attack vectors:**
- Reading the token file via a path traversal in a filesystem tool
- Exfiltrating the token from process environment or memory
- Sniffing the token on the network (if not using TLS)

**Severity:** High

### T5: Denial of service via rate limit abuse

**Description:** An attacker floods the firewall with requests to exhaust the rate limit budget, blocking legitimate tool calls.

**Attack vectors:**
- Rapid-fire requests to consume the token-bucket budget
- Distributed requests from multiple compromised agents
- Oversized request bodies to consume memory/CPU

**Severity:** Medium

## Mitigations in place

| Threat | Mitigation | Implementation |
|---|---|---|
| T1: Policy bypass | Default-deny policy | Tools must be explicitly listed in the allow list. Unknown tools are rejected. Deny list is evaluated before allow list. |
| T2: Path traversal | Path canonicalization and validation | `filepath.Clean` + `filepath.Abs` resolve all `../` sequences. Null bytes are rejected. Paths are matched against allowlist/denylist after canonicalization. |
| T3: Argument injection | Typed, allowlisted argument contracts and length limits | Per-tool `args` rules enforce JSON types, required fields, bounds, and patterns. Undeclared dangerous and credential aliases fail closed; `args_blocklist` inspects raw/nested strings without JSON HTML-escaping bypasses. |
| T4: Token exfiltration | Scoped file-backed identities with constant-time comparison | Unique tokens bind audited identities to explicit evaluator/observer/administrator roles. Administrator cannot be combined with other roles; token files are owner-only and never supplied as token values in the environment. |
| T5: DoS via rate limiting | Process-wide token-bucket rate limiter | Configurable `requests_per_minute` with burst support. Request body size capped at 64 KiB via `http.MaxBytesReader`. |
| General | Minimal attack surface | Single static binary with no runtime package dependency and no shell execution path. Source and systemd default to loopback; the container must be host-published to loopback or placed behind an authenticated TLS proxy. Systemd adds DynamicUser, syscall filtering, and resource limits. |
| General | Audit logging | Every policy decision is durably appended and synced to a structured JSONL audit trail. Canonical credential aliases are replaced with a constant (no dictionary-oracle hash), prompt/response and oversized values are redacted, and an audit failure fails the request closed. |

## Residual risks

| Risk | Description | Recommended mitigation |
|---|---|---|
| R1: Symlink race conditions | Path validation now resolves symlinks for the deepest existing prefix, but a filesystem race could still swap a path between evaluation and tool execution. | Mount allowlisted directories with `nosymfollow` and ensure the executor opens files relative to a trusted directory descriptor. |
| R2: Unicode / encoded path tricks | Percent-encoded traversal and known Unicode path confusables are rejected before matching; other filesystem-specific canonicalization quirks may still exist. | Keep deny-by-default policies and add platform-specific tests for any new execution environment. |
| R3: TOCTOU on policy reload | A race between reading the policy file and applying it could lead to inconsistent state. | The current `sync.RWMutex` serializes reads and writes, but file-level TOCTOU remains if the file is modified during read. Use atomic file replacement (rename). |
| R4: No TLS by default | The firewall listens on plain HTTP. If exposed beyond localhost, tokens and tool call data are transmitted in cleartext. | Default bind is `127.0.0.1` (localhost only). For multi-host deployments, use a reverse proxy with mTLS termination. |
| R5: Single-point rate limiter | The rate limiter is in-process and per-instance. Multiple firewall instances do not share rate limit state. | Acceptable for single-appliance deployment. For distributed deployments, use an external rate limiter (e.g., envoy, nginx). |
| R6: Local credential identity only | Scoped credentials provide local identities and RBAC but are long-lived bearer secrets, not tenant identity or proof of workload instance. | Use multiple least-privilege identities locally; for cross-host or tenant use, add short-lived workload identity or an identity-aware mTLS proxy and rotate tokens. |
| R7: Decision/enforcement gap | The service returns a decision but does not execute or sandbox the downstream tool. A caller could ignore a denial or alter arguments after evaluation. | Make the firewall a mandatory gateway and bind the approved request to execution in the integrating runtime. |
