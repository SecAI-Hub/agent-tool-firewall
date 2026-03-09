# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-09

### Added

- Default-deny policy gateway for LLM/AI agent tool calls
- YAML-based policy with hot-reload via SIGHUP or `/v1/reload` endpoint
- Path traversal protection with canonicalization, null-byte rejection, and blocklist matching
- Argument filtering with configurable blocklist patterns and length limits
- Sliding-window rate limiter with configurable burst
- Bearer token authentication for mutating endpoints (fail-closed)
- Structured JSONL audit logging for all policy decisions
- `securectl` CLI companion for policy management
- Container image with multi-arch support (amd64/arm64)
- Systemd unit with strict sandboxing (DynamicUser, PrivateNetwork, seccomp)
- Seccomp profile for minimal syscall allowlist
- Signed releases with cosign keyless signing and SLSA provenance
- Threat model documentation
- mTLS deployment guidance for multi-host setups

### Security

- Default-deny: unlisted tools are rejected
- Deny list evaluated before allow list
- Constant-time token comparison prevents timing attacks
- 64 KB request body limit prevents memory exhaustion
- Localhost-only bind by default (127.0.0.1:8475)
