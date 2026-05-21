.PHONY: all build clean test run-auth run-vault run-policy run-approval run-audit run-ssh-proxy run-gateway tidy \
       docker-build docker-up docker-down docker-logs docker-ps docker-reset

SERVICES := auth-service vault-service policy-service approval-service audit-service ssh-proxy rdp-proxy api-gateway tacacs-service pam-cli
BIN := bin

all: build

tidy:
	go mod tidy

build: tidy
	@mkdir -p $(BIN)
	@for s in $(SERVICES); do \
		echo "Building $$s..."; \
		go build -trimpath -ldflags "-s -w" -o $(BIN)/$$s ./cmd/$$s || exit 1; \
	done
	@echo "All services built into $(BIN)/"

test:
	go test ./...

clean:
	rm -rf $(BIN) data recordings

# Local dev runners (run each in its own terminal)
run-auth:
	PAM_DB=./data/pam.db go run ./cmd/auth-service

run-vault:
	PAM_DB=./data/pam.db go run ./cmd/vault-service

run-policy:
	PAM_DB=./data/pam.db go run ./cmd/policy-service

run-approval:
	PAM_DB=./data/pam.db go run ./cmd/approval-service

run-audit:
	PAM_DB=./data/pam.db go run ./cmd/audit-service

run-ssh-proxy:
	PAM_DB=./data/pam.db go run ./cmd/ssh-proxy

run-gateway:
	PAM_DB=./data/pam.db go run ./cmd/api-gateway

run-tacacs:
	PAM_DB=./data/pam.db go run ./cmd/tacacs-service

COMPOSE := docker compose -f deploy/docker/docker-compose.yml

docker-build:
	@test -f deploy/docker/.env || cp deploy/docker/.env.example deploy/docker/.env
	@test -f deploy/docker/secrets.env || cp deploy/docker/secrets.env.example deploy/docker/secrets.env
	$(COMPOSE) build

docker-up:
	@test -f deploy/docker/.env || cp deploy/docker/.env.example deploy/docker/.env
	@test -f deploy/docker/secrets.env || cp deploy/docker/secrets.env.example deploy/docker/secrets.env
	$(COMPOSE) up --build -d

docker-down:
	$(COMPOSE) down

docker-logs:
	$(COMPOSE) logs -f

docker-ps:
	$(COMPOSE) ps

docker-reset:
	$(COMPOSE) down -v
