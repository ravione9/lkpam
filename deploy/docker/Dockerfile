# Multi-stage build: compile all services, run on minimal Alpine.
FROM golang:1.22-alpine AS build

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go mod tidy

ARG SERVICES="auth-service vault-service policy-service approval-service audit-service ssh-proxy rdp-proxy api-gateway tacacs-service radius-service pam-cli"
RUN mkdir -p /out && \
    for svc in $SERVICES; do \
        echo "building $svc"; \
        CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/$svc ./cmd/$svc || exit 1; \
    done

FROM alpine:3.20

RUN apk add --no-cache ca-certificates wget su-exec tzdata netcat-openbsd libcap \
    && addgroup -S pam \
    && adduser -S pam -G pam

WORKDIR /app
COPY --from=build /out/ /app/
COPY deploy/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
    && mkdir -p /data /recordings \
    && chown -R pam:pam /data /recordings \
    && setcap 'cap_net_bind_service=+ep' /app/tacacs-service

VOLUME ["/data", "/recordings"]

EXPOSE 8080 8081 8082 8083 8084 8085 8086 2222 49 1812/udp 1813/udp

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/api-gateway"]
