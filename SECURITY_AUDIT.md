# Security and production-readiness audit

Audit date: 2026-08-02

## Scope and method

This review covered policy parsing and evaluation, path controls, request validation,
authentication, rate limiting, audit durability, HTTP handling, container and systemd
deployment, CI/release workflows, schemas, tests, dependencies, and documentation. It
combined manual threat-oriented review with race-enabled tests, `go vet`,
`govulncheck`, secret scanning, dependency/misconfiguration scanning, and container
builds. It is a point-in-time engineering audit, not a formal certification.

## Findings addressed

| Severity | Finding | Remediation |
|---|---|---|
| Critical | Evaluation and statistics endpoints were available without authentication and the daemon could start without a credential. | Every endpoint except `/health` now requires a file-backed credential; strict local identities bind exact evaluator/observer/administrator roles, administrative credentials cannot evaluate, and startup fails closed on missing, duplicate, weak, or over-broad role configuration. |
| Critical | Lexical path checks could be bypassed by prefix lookalikes, encoded traversal, symlinks, or absent path parameters. | Paths must be absolute and present when restrictions apply; decoding, boundary-safe containment, deepest-existing-prefix symlink resolution, null-byte rejection, and path-confusable rejection run before policy matching. |
| High | Malformed or permissive policy documents could weaken the default-deny posture. | Policies use bounded strict YAML decoding, reject unknown fields/multiple documents/duplicates/conflicts, require version 1 and `default_action: deny`, validate patterns, and cap rule counts and lengths. |
| High | Audit failures could allow an evaluated call without a durable security record, and sensitive argument values were retained. | Audit writes are complete and synced; startup and decisions fail closed on audit failure, while secret-like keys and oversized/prompt/response values are redacted. |
| High | Request bodies and nested values were weakly bounded, leaving parsing and memory-abuse paths. | Bodies are capped at 64 KiB, JSON is strict and single-valued, legacy arguments normalize safely, and identifier/count/value limits are enforced. |
| Medium | Configured burst behavior was not represented by an effective process-wide limiter. | A concurrency-safe token bucket enforces requests-per-minute and burst settings and is reset safely on policy changes. |
| Medium | Reload errors could disclose server details or activate a partially valid policy. | Reload validates the complete policy before swapping it and returns generic client-facing errors. |
| Medium | Build/release dependencies, container bases, and final-stage package installation were mutable. | CI/release actions and container bases are immutable-pinned; the CA bundle is copied from the pinned builder and the final stage performs no live package-manager install. CI includes race tests, formatting, vet, `gosec`, `govulncheck`, Gitleaks, Trivy, image scanning, signed releases, checksums, and provenance. |
| Medium | Deployment defaults conflicted with the TCP listener and lacked a bundled safe policy. | The systemd network restrictions now match the listener, credentials are read-only with a restrictive umask, and the image ships a valid default-deny policy and non-root health check. |
| High | Untyped tool parameters, undeclared credential/execution fields, and JSON HTML escaping could bypass a tool's contract or literal argument blocklist. | Policies support per-tool JSON type, required, length, pattern, and redaction rules; configured rules form a complete allowlist, undeclared dangerous/credential aliases fail closed, and blocklists inspect bounded raw and recursively nested strings plus non-HTML-escaped JSON. |
| High | Nested or camel/kebab/snake-case secrets, audit-file replacement/hardlinks, broad permissions, and unbounded growth weakened the audit boundary. Deterministic short secret hashes also enabled offline guessing. | Credential aliases are canonicalized recursively and replaced with a constant—never an unkeyed fingerprint—while prompt/content redaction retains only length. The owner-only single-link audit-file identity is rechecked before every append and writes fail closed at 256 MiB. |
| Medium | Container loopback binding prevented published-port operation, service credentials were manually exposed under `/run`, and any `v*` tag could start a release or produce colliding/moving OCI aliases. | The image now binds its container interface while examples publish host loopback, CI exercises the host port, systemd uses `LoadCredential=`, and least-privilege releases require a GitHub-verified annotated strict-SemVer tag on `main` plus exact-commit security gates; exact `+`→`_` and full-SHA OCI tags are immutable and collision-free. |

## Remaining risks and recommendations

- This service makes a decision; it does not sandbox or execute a tool. The integrating
  runtime must make it a mandatory gateway and must bind the exact evaluated arguments
  to execution.
- Filesystem contents can change after evaluation. Executors should use descriptor-based
  access rooted in approved directories, avoid following links, and apply OS sandboxing.
- Scoped local credentials provide audited identities and administrative RBAC, but bearer
  tokens remain long-lived and do not prove tenant or workload instance identity. Use short-lived
  workload identity or an identity-aware TLS/mTLS proxy for cross-host/multi-tenant deployments.
- Rate-limit state is in memory and per instance. Use a trusted distributed limiter before
  horizontally scaling or exposing the gateway to untrusted networks.
- Regex and filesystem behavior should be qualified on every newly supported platform;
  the committed release path currently targets Linux.
- Secret scanning/push protection, Dependabot security updates, and a baseline main-integrity
  ruleset are enabled. Required PR/status/reviewer gates and protected release environments
  still need an independently approved repository ruleset.

## Validation evidence

The audited worktree's 50 top-level tests passed `go test -race -count=1 ./...`, `go vet ./...`,
`go mod verify`, `gosec@v2.28.0 -severity medium -confidence medium ./...`, and
`govulncheck@v1.3.0` under Go 1.26.5. Gitleaks 8.30.1
reported no worktree or history leaks. Trivy 0.70.0 reported no High/Critical
source, dependency, container, or image findings under the committed CI policy.
All YAML/JSON parsed, all workflow actions were full-SHA pinned and their tag SHAs
were remotely verified, and the non-root read-only image passed a runtime health,
authentication, and API smoke test with the supplied seccomp profile.
Fedora 44's `systemd-analyze verify` accepted the supplied service unit.

## Release gate

Before each release, run the committed CI workflow, review scanner results, test a policy
reload and an induced audit-write failure, verify runtime limits, and verify published
checksums, Sigstore signatures, provenance, and container digests. Qualify the supplied
systemd restrictions on each target Fedora/RHEL release before rollout.
