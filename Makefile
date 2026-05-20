.PHONY: all build clean test run-auth run-vault run-policy run-approval run-audit run-ssh-proxy run-gateway tidy

SERVICES := auth-service vault-service policy-service approval-service audit-service ssh-proxy api-gateway tacacs-service pam-cli
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

docker-build:
	docker compose -f deploy/docker/docker-compose.yml build

docker-up:
	docker compose -f deploy/docker/docker-compose.yml up -d

docker-down:
	docker compose -f deploy/docker/docker-compose.yml down
