# agent-tool-firewall

[![CI](https://github.com/SecAI-Hub/agent-tool-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/SecAI-Hub/agent-tool-firewall/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/SecAI-Hub/agent-tool-firewall)](https://goreportcard.com/report/github.com/SecAI-Hub/agent-tool-firewall)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Default-deny policy gateway for LLM and agent tool calls.**

agent-tool-firewall is a lightweight HTTP service that sits between your AI agent/LLM and the tools it can invoke. Every tool call is evaluated against a YAML policy before execution. If the policy says no, the call is blocked and audit-logged.

## Why

LLMs and AI agents increasingly call external tools (file I/O, shell commands, APIs). Without a policy layer, a prompt injection or jailbreak can escalate to arbitrary code execution. agent-tool-firewall enforces **default-deny**: tools must be explicitly allowlisted before they can run.

### Use cases

- Local AI assistants (Claude, GPT, open-source LLMs)
- MCP server gateways
- RAG pipelines with tool access
- Desktop copilots
- CI/CD agent sandboxes
- Any system where an LLM invokes tools on behalf of a user

## Features

| Feature | Description |
|---|---|
| Default-deny policy | Tools blocked unless explicitly allowed |
| Path allowlisting | Filesystem access restricted to permitted directories |
| Traversal protection | Catches `../`, null bytes, symlink escapes |
| Argument filtering | Block dangerous patterns in tool arguments |
| Rate limiting | Sliding-window rate limiter (configurable RPM) |
| Structured audit log | JSONL audit trail for every decision |
| Hot reload | Reload policy without restart (`POST /v1/reload`) |
| Bearer token auth | Optional service-to-service authentication |
| Zero dependencies | Single static binary, only needs a policy YAML file |

## Quick start

### 1. Write a policy

```yaml
# policy.yaml
version: 1
tools:
  default: "deny"
  rate_limit:
    requests_per_minute: 120
  allow:
    - name: "filesystem.read"
      paths_allowlist:
        - "/home/user/documents/**"
      paths_denylist:
        - "/etc/shadow"
        - "/etc/passwd"
      max_arg_length: 4096
    - name: "web.search"
      args_blocklist:
        - "password"
        - "secret"
  deny:
    - name: "shell.exec"
    - name: "process.spawn"
```

### 2. Run

```bash
# From source
go build -o agent-tool-firewall .
POLICY_PATH=./policy.yaml ./agent-tool-firewall

# With Docker/Podman
podman build -t agent-tool-firewall .
podman run -v ./policy.yaml:/etc/secure-ai/policy/policy.yaml:ro \
  -p 8475:8475 agent-tool-firewall
```

### 3. Evaluate a tool call

```bash
curl -s -X POST http://127.0.0.1:8475/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool":"filesystem.read","params":{"path":"/home/user/documents/notes.txt"}}' | jq .
```

```json
{ "allowed": true }
```

```bash
curl -s -X POST http://127.0.0.1:8475/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"tool":"shell.exec","params":{"cmd":"rm -rf /"}}' | jq .
```

```json
{ "allowed": false, "reason": "tool is explicitly denied" }
```

## API

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | No | Health check + request counters |
| `/v1/evaluate` | POST | No | Evaluate a tool call against policy |
| `/v1/stats` | GET | No | Aggregated security statistics |
| `/v1/reload` | POST | Bearer | Hot-reload the policy file |

### POST /v1/evaluate

**Request:**
```json
{
  "tool": "filesystem.read",
  "params": {
    "path": "/vault/user_docs/readme.txt"
  }
}
```

**Response:**
```json
{
  "allowed": true
}
```

Or when denied:
```json
{
  "allowed": false,
  "reason": "path not in allowlist"
}
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `BIND_ADDR` | `127.0.0.1:8475` | Listen address |
| `POLICY_PATH` | `/etc/secure-ai/policy/policy.yaml` | Path to YAML policy file |
| `AUDIT_LOG_PATH` | `/var/lib/secure-ai/logs/tool-firewall-audit.jsonl` | Audit log output |
| `SERVICE_TOKEN_PATH` | `/run/secure-ai/service-token` | Bearer token file for `/v1/reload` |

## Policy reference

See [examples/policy.yaml](examples/policy.yaml) for a fully annotated example.

### Evaluation order

1. **Rate limit** -- reject if over budget
2. **Deny list** -- explicit denials always win
3. **Allow list** -- tool must be listed (in default-deny mode)
4. **Argument validation** -- length limits, blocked patterns
5. **Path security** -- clean, resolve, check denylist, check allowlist

### Path matching

- `/vault/user_docs/**` -- recursive match (everything under the directory)
- Paths are canonicalized (`filepath.Clean` + `filepath.Abs`) before matching
- `../` traversal and null-byte injection are caught and rejected

## Hardening

When deploying in production, consider:

- **Systemd sandboxing:** See [deploy/systemd/](deploy/systemd/) for a hardened unit file with `DynamicUser=yes`, `PrivateNetwork=yes`, `MemoryDenyWriteExecute=yes`, and syscall filtering.
- **Seccomp profile:** See [deploy/seccomp/](deploy/seccomp/) for a strict seccomp profile that blocks exec syscalls.
- **Service token:** Set `SERVICE_TOKEN_PATH` to require Bearer auth on the reload endpoint.

## Multi-host deployment

By default, agent-tool-firewall binds to `127.0.0.1:8475` (localhost only). This is intentional: in appliance mode, only local processes should reach the firewall. **Never expose the firewall directly to untrusted networks.**

For multi-host deployments where the LLM agent runs on a different machine than the firewall, place agent-tool-firewall behind a reverse proxy that terminates mTLS (mutual TLS). This ensures:

- **Encryption in transit** -- tool call data and bearer tokens are not sent in cleartext.
- **Client authentication** -- only agents with a valid client certificate can reach the firewall.
- **Network segmentation** -- the firewall process itself never handles TLS, keeping its attack surface minimal.

### Example: nginx mTLS termination

```nginx
upstream tool_firewall {
    server 127.0.0.1:8475;
}

server {
    listen 8476 ssl;

    # Server certificate and key
    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    # Require client certificates (mTLS)
    ssl_client_certificate /etc/nginx/certs/ca.crt;
    ssl_verify_client on;

    # TLS hardening
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://tool_firewall;
        proxy_set_header X-Client-DN $ssl_client_s_dn;
        proxy_set_header X-Forwarded-For $remote_addr;

        # Restrict request body size
        client_max_body_size 64k;
    }
}
```

With this setup, the agent connects to `https://<firewall-host>:8476` with its client certificate, and nginx forwards validated requests to the firewall on localhost.

For Envoy, the equivalent configuration uses `transport_socket` with `require_client_certificate: true` in the downstream TLS context.

## Integration with SecAI OS

agent-tool-firewall is used as a core component of [SecAI OS](https://github.com/SecAI-Hub/SecAI_OS), a bootable local-first AI appliance. In that context it runs as a systemd service with strict sandboxing, seccomp filtering, and no network access.

## License

Apache-2.0. See [LICENSE](LICENSE).
