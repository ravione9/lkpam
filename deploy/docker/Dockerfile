# Multi-stage build: compile once, copy each binary into a minimal runtime image.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy
RUN mkdir -p /out && \
    for svc in auth-service vault-service policy-service approval-service audit-service ssh-proxy api-gateway pam-cli; do \
        echo "building $svc"; \
        CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/$svc ./cmd/$svc; \
    done

FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=build /out/ /app/
EXPOSE 8080 8081 8082 8083 8084 8085 2222
USER nonroot:nonroot
ENTRYPOINT ["/app/api-gateway"]
