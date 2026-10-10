FROM docker.io/library/golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/agent-tool-firewall .

FROM docker.io/library/alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
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
