# Docker deployment

Run the full PAM stack with Docker Compose — admin UI, API gateway, vault,
policy engine, approval workflow, audit, and SSH proxy.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS)
  or Docker Engine + Compose v2 (Linux)
- 2 GB free disk space

## Quick start

From the **repository root** (`pam-platform/`):

```bash
# 1. Create env file (edit secrets before production)
cp deploy/docker/.env.example deploy/docker/.env

# 2. Build and start all services
docker compose -f deploy/docker/docker-compose.yml up --build -d

# 3. Open the admin console
#    http://localhost:8080
#    Default login: admin / admin
```

Or use Make:

```bash
make docker-up      # build + start detached
make docker-logs    # follow logs
make docker-down    # stop and remove containers
```

## What gets exposed

| Port | Service | Purpose |
|------|---------|---------|
| **8080** | API gateway | Admin UI + REST API |
| **2222** | SSH proxy | Privileged SSH sessions |

All other services (auth, vault, policy, …) run on the internal `pam-net`
network only.

## First-time setup in the UI

1. Sign in at http://localhost:8080 (`admin` / `admin`).
2. Go to **Targets** → **Add target** (name, kind, host, port, tier).
3. Connect via SSH:
   ```bash
   ssh -p 2222 admin@your-target-name@localhost
   ```
4. Approve JIT requests under **Access requests** if the target tier requires it.

## Environment variables

Copy `deploy/docker/.env.example` to `deploy/docker/.env`:

| Variable | Required | Description |
|----------|----------|-------------|
| `PAM_JWT_SECRET` | Yes (prod) | HS256 signing secret |
| `PAM_MASTER_KEY` | Recommended | Base64 32-byte vault key. If unset, a key is auto-created at `/data/.master_key` on first boot (shared across all containers via the `pam-data` volume). |
| `PAM_ADMIN_USER` | No | Bootstrap admin username (default `admin`) |
| `PAM_ADMIN_PASS` | No | Bootstrap admin password (default `admin`) |
| `PAM_HTTP_PORT` | No | Host port for UI (default `8080`) |
| `PAM_SSH_PORT` | No | Host port for SSH proxy (default `2222`) |

Generate secrets:

```bash
# JWT secret
openssl rand -hex 32

# Vault master key (paste into PAM_MASTER_KEY in .env)
openssl rand -base64 32
```

## Optional: TACACS+

Start the TACACS+ AAA server for network devices:

```bash
docker compose -f deploy/docker/docker-compose.yml --profile tacacs up -d
```

Point devices at host port **49** with shared secret `PAM_TACACS_SECRET`.

## Data persistence

| Volume | Contents |
|--------|----------|
| `pam-data` | SQLite database, audit JSONL |
| `pam-rec` | SSH session recordings |

```bash
# List volumes
docker volume ls | grep pam

# Reset everything (destroys data)
docker compose -f deploy/docker/docker-compose.yml down -v
```

## Troubleshooting

**Services not starting**

```bash
docker compose -f deploy/docker/docker-compose.yml ps
docker compose -f deploy/docker/docker-compose.yml logs gateway
```

**Health checks failing**

Wait ~30s on first boot (DB migration + vault CA init). Check auth first:

```bash
docker compose -f deploy/docker/docker-compose.yml logs auth
```

**SSH proxy connection refused**

Ensure `ssh-proxy` is healthy and a target exists in the UI:

```bash
docker compose -f deploy/docker/docker-compose.yml logs ssh-proxy
```

**Vault decrypt errors after restart**

Set a fixed `PAM_MASTER_KEY` in `.env` before the first run. If the vault
was already initialized with an ephemeral key, reset volumes:

```bash
docker compose -f deploy/docker/docker-compose.yml down -v
# set PAM_MASTER_KEY in .env, then up again
```

## Production notes

This compose file is suitable for **dev / lab / PoC**. Before production:

- Replace SQLite with Postgres (shared `PAM_DB` DSN)
- Set strong `PAM_JWT_SECRET` and `PAM_MASTER_KEY`
- Change default admin password immediately
- Put TLS in front of port 8080 (nginx, Traefik, cloud LB)
- Do not expose internal service ports
