FROM docker.io/library/golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent-tool-firewall .

FROM docker.io/library/alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
LABEL org.opencontainers.image.source="https://github.com/SecAI-Hub/agent-tool-firewall" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN install -d -o 65534 -g 65534 -m 0750 \
    /etc/secure-ai/policy /etc/ssl/certs /var/lib/secure-ai/logs
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --chown=65534:65534 policies/default-policy.yaml /etc/secure-ai/policy/policy.yaml
COPY --from=build /out/agent-tool-firewall /usr/local/bin/agent-tool-firewall
ENV BIND_ADDR=0.0.0.0:8475 \
    ALLOW_REMOTE_BIND=true
USER 65534:65534
EXPOSE 8475
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
  CMD wget -q -T 3 -O - http://127.0.0.1:8475/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/agent-tool-firewall"]
