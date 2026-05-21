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
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml up --build -d

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
| **49** | TACACS+ | Network device AAA (host port; override with `PAM_TACACS_PORT`) |

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
| `PAM_TACACS_PORT` | No | Host port for TACACS+ (default `49`) |
| `PAM_TACACS_SECRET` | Yes (prod) | Shared secret for network devices |

Generate secrets:

```bash
# JWT secret
openssl rand -hex 32

# Vault master key (paste into PAM_MASTER_KEY in .env)
openssl rand -base64 32
```

## TACACS+

TACACS+ starts automatically with the stack. Point network devices at the PAM host on port **49** (or `PAM_TACACS_PORT`) with shared secret `PAM_TACACS_SECRET`.

```bash
# Verify the service is listening (after docker compose up)
docker compose -f deploy/docker/docker-compose.yml ps tacacs
docker compose -f deploy/docker/docker-compose.yml logs tacacs --tail 20
```

Cisco IOS example (replace `192.168.24.253` and secret):

```
aaa new-model
aaa group server tacacs+ PAM
 server-private 192.168.24.253 key YOUR-PAM_TACACS_SECRET
aaa authentication login default group PAM local
```

If port 49 is blocked on the host firewall, open it:

```bash
# Linux (ufw example)
sudo ufw allow 49/tcp
```

To use a non-standard host port (e.g. 4949), set `PAM_TACACS_PORT=4949` in `.env` and configure devices with `port 4949`.

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

**`The "mL8Q" variable is not set` (or similar)**

One of your secrets in `deploy/docker/.env` contains a **`$` character**. Docker Compose treats `$name` as a variable reference and breaks the value.

Fix either:

1. **Escape each `$` as `$$`** in `.env` (e.g. secret `ab$cd` → write `ab$$cd`), or  
2. **Regenerate secrets without `$`** (recommended for TACACS/JWT):
   ```bash
   openssl rand -hex 32    # for PAM_JWT_SECRET / PAM_TACACS_SECRET
   ```

Then restart:

```bash
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml up -d --build tacacs
```

**TACACS container missing (`ps tacacs` shows empty)**

Pull latest code (TACACS is included by default), then rebuild:

```bash
git pull origin main
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml up -d --build tacacs
docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml logs tacacs --tail 20
```

Expect: `tacacs+ listening on :1049`

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
