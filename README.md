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
| Typed tool contracts | Per-tool JSON types, required fields, limits, patterns, and audit redaction; typed contracts reject every undeclared field |
| Rate limiting | Process-wide token-bucket limiter (configurable RPM and burst) |
| Structured audit log | JSONL audit trail for every decision |
| Hot reload | Reload policy without restart (`POST /v1/reload`) |
| Scoped bearer identities | File-backed credentials bind stable audit identities to exact `evaluator`, `observer`, or isolated `administrator` roles; only `/health` is public |
| Privacy-preserving audit | Prompt, response, credential, and oversized values are redacted before durable JSONL logging; credential aliases use constant redaction without guessable hashes |
| Strict parsing | Bounded JSON/YAML, unknown-field rejection, one-document enforcement, and validated policy limits |

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
      args:
        - name: "path"
          type: "string"
          required: true
          max_length: 4096
      paths_allowlist:
        - "/home/user/documents/**"
      paths_denylist:
        - "/etc/shadow"
        - "/etc/passwd"
      max_arg_length: 4096
    - name: "web.search"
      args:
        - name: "query"
          type: "string"
          required: true
          max_length: 1024
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
openssl rand -hex 32 > ./service-token
openssl rand -hex 32 > ./admin-token
chmod 600 ./service-token ./admin-token
install -d -m 700 ./logs
POLICY_PATH=./policy.yaml \
SERVICE_TOKEN_PATH=./service-token \
ADMIN_TOKEN_PATH=./admin-token \
AUDIT_LOG_PATH="$PWD/audit.jsonl" \
./agent-tool-firewall

# With Docker/Podman
podman build -t agent-tool-firewall .
podman run --read-only --cap-drop=ALL --security-opt=no-new-privileges \
  --userns=keep-id:uid=65534,gid=65534 \
  --pids-limit=64 -p 127.0.0.1:8475:8475 \
  -v ./policy.yaml:/etc/secure-ai/policy/policy.yaml:ro,Z \
  -v ./service-token:/run/secure-ai/service-token:ro,Z \
  -v ./admin-token:/run/secure-ai/admin-token:ro,Z \
  -v ./logs:/var/lib/secure-ai/logs:Z \
  agent-tool-firewall
```

The container image listens on `0.0.0.0:8475` so published ports work; the
example deliberately publishes only to host loopback. Source and systemd runs
remain loopback-only unless remote binding is explicitly enabled.
The rootless Podman example maps the invoking Fedora user to the image's numeric
UID/GID so the owner-only token and audit directory remain accessible without
loosening their permissions; `:Z` applies a private SELinux label.

### 3. Evaluate a tool call

```bash
curl -s -X POST http://127.0.0.1:8475/v1/evaluate \
  -H "Authorization: Bearer $(cat ./service-token)" \
  -H "Content-Type: application/json" \
  -d '{"tool":"filesystem.read","params":{"path":"/home/user/documents/notes.txt"}}' | jq .
```

```json
{ "allowed": true }
```

```bash
curl -s -X POST http://127.0.0.1:8475/v1/evaluate \
  -H "Authorization: Bearer $(cat ./service-token)" \
  -H "Content-Type: application/json" \
  -d '{"tool":"shell.exec","params":{"cmd":"rm -rf /"}}' | jq .
```

```json
{ "allowed": false, "reason": "tool is explicitly denied" }
```

## API

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | No | Minimal liveness check |
| `/v1/evaluate` | POST | `evaluator` | Evaluate a tool call against policy |
| `/v1/stats` | GET | `observer` | Aggregated security statistics |
| `/v1/reload` | POST | `administrator` | Hot-reload the policy file |

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
| `ALLOW_REMOTE_BIND` | unset | Exact `true` permits a non-loopback listener |
| `POLICY_PATH` | `/etc/secure-ai/policy/policy.yaml` | Path to YAML policy file |
| `AUDIT_LOG_PATH` | `/var/lib/secure-ai/logs/tool-firewall-audit.jsonl` | Audit log output |
| `SERVICE_TOKEN_PATH` | `/run/secure-ai/service-token` | Compatibility credential with `evaluator` and `observer` roles |
| `ADMIN_TOKEN_PATH` | `/run/secure-ai/admin-token` | Separate credential with only the `administrator` role |
| `CREDENTIALS_CONFIG_PATH` | unset | Optional strict YAML credential/identity configuration replacing both compatibility credentials |

Startup fails if credentials or the audit log cannot be opened. Without a credential
configuration, distinct service and administrative tokens are mandatory. For multiple
callers, set `CREDENTIALS_CONFIG_PATH` to a file following
[`deploy/credentials.example.yaml`](deploy/credentials.example.yaml). Each entry binds an
audited identity to explicit roles and an absolute owner-only token file; the configuration
path itself must also be absolute. Token values and
identities must be unique; administrator cannot be combined with another role. Tokens must
contain 32–4096 non-whitespace bytes. Only SHA-256 token digests remain in process after
startup, so authentication compares fixed-length values. Policies remain strict version 1/default-deny.

## Policy reference

See [examples/policy.yaml](examples/policy.yaml) for a fully annotated example.

### Evaluation order

1. **Rate limit** -- reject if over budget
2. **Deny list** -- explicit denials always win
3. **Allow list** -- tool must be listed (in default-deny mode)
4. **Argument validation** -- JSON types, required fields, per-argument limits, patterns, and blocked values. When `args` is present it is a complete allowlist; undeclared execution, network, content, and path fields otherwise fail closed unless a path policy explicitly constrains them.
5. **Path security** -- clean, resolve, check denylist, check allowlist

### Path matching

- `/vault/user_docs/**` -- recursive match (everything under the directory)
- Paths are canonicalized through the deepest existing filesystem prefix before matching
- Request paths must be absolute
- `../` traversal and null-byte injection are caught and rejected
- Symlink escapes, percent-encoding tricks, Unicode separator confusables, prefix lookalikes, missing path arguments, and alternate path keys are denied

## Hardening

When deploying in production, consider:

- **Systemd sandboxing:** See [deploy/systemd/](deploy/systemd/) for a hardened unit with `DynamicUser=yes`, loopback binding, `LoadCredential=` token delivery, `MemoryDenyWriteExecute=yes`, and syscall filtering.
- **Seccomp profile:** See [deploy/seccomp/](deploy/seccomp/) for a tested syscall allowlist. OCI startup requires `execve`; the service itself contains no subprocess execution path.
- **Scoped credentials:** Keep evaluator, observer, and administrator secrets separate. A
  compatibility service credential has evaluator+observer only; it can never reload policy.
- **Audit durability:** audit files are owner-only (`0600`), single-link regular files. Identity and permissions are rechecked before every append and the log fails closed at 256 MiB. Rotate it while the service is stopped.

For systemd, install the credential source at
`/etc/agent-tool-firewall/service-token` and `/etc/agent-tool-firewall/admin-token` as
distinct root-owned `0600` files. The service
manager copies it into the unit's protected credential directory; the token is
not passed in the process environment or exposed through a manually managed
shared `/run` path.

## Multi-host deployment

By default, agent-tool-firewall binds to `127.0.0.1:8475` (localhost only). This is intentional: in appliance mode, only local processes should reach the firewall. **Never expose the firewall directly to untrusted networks.**

For multi-host deployments where the LLM agent runs on a different machine than the firewall, set `ALLOW_REMOTE_BIND=true` only when placing agent-tool-firewall behind a reverse proxy that terminates mTLS (mutual TLS). This ensures:

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

agent-tool-firewall is used as a core component of [SecAI OS](https://github.com/SecAI-Hub/SecAI_OS), a bootable local-first AI appliance. In that context it runs as a loopback-only systemd service with strict sandboxing and syscall filtering.

See [SECURITY.md](SECURITY.md), [THREAT_MODEL.md](THREAT_MODEL.md), and the
[security audit](SECURITY_AUDIT.md) before production deployment.

## License

Apache-2.0. See [LICENSE](LICENSE).
