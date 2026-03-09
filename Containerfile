FROM docker.io/library/golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /agent-tool-firewall .

FROM docker.io/library/alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /agent-tool-firewall /usr/local/bin/agent-tool-firewall
USER 65534:65534
EXPOSE 8475
ENTRYPOINT ["agent-tool-firewall"]
