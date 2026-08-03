# Contributing to agent-tool-firewall

## Prerequisites

| Tool | Version |
|---|---|
| Go | 1.25+ (CI uses 1.26.5) |
| git | 2.x |

## Local development

```bash
git clone https://github.com/SecAI-Hub/agent-tool-firewall.git
cd agent-tool-firewall
go build .
go test -v -race ./...
go vet ./...
```

## Running locally

```bash
openssl rand -hex 32 > ./service-token
openssl rand -hex 32 > ./admin-token
chmod 600 ./service-token ./admin-token
POLICY_PATH=./examples/policy.yaml \
SERVICE_TOKEN_PATH=./service-token \
ADMIN_TOKEN_PATH=./admin-token \
AUDIT_LOG_PATH="$PWD/audit.jsonl" \
./agent-tool-firewall
```

## Tests

```bash
go test -v -race -count=1 ./...
```

All tests must pass before submitting a PR.

## Code style

- Run `gofmt -s -w .` before committing.
- Run `go vet ./...` to catch common issues.
- Keep the single-file structure unless there is a strong reason to split.

## Pull request process

1. Fork the repo and create a feature branch.
2. Make your changes with clear, focused commits.
3. Ensure all tests pass (`go test -race ./...`).
4. Open a PR against `main`.

## Commit message format

```
<type>: <short summary>

<optional body>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `security`.

## Security issues

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities.
