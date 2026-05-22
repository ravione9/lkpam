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
# 1. Create config files (edit secrets.env before production)
cp deploy/docker/.env.example deploy/docker/.env
cp deploy/docker/secrets.env.example deploy/docker/secrets.env
chmod 600 deploy/docker/secrets.env

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

Copy `deploy/docker/.env.example` → `.env` and `secrets.env.example` → `secrets.env`:

| File | Purpose |
|------|---------|
| `.env` | Host ports and URLs only (safe for Compose `${VAR}` substitution) |
| `secrets.env` | JWT, vault key, TACACS secret, admin password — **may contain `$` safely** |

| Variable | File | Required | Description |
|----------|------|----------|-------------|
| `PAM_JWT_SECRET` | secrets.env | Yes (prod) | HS256 signing secret |
| `PAM_MASTER_KEY` | secrets.env | Recommended | Base64 32-byte vault key (auto-created on first boot if blank) |
| `PAM_TACACS_SECRET` | secrets.env | Yes (prod) | Shared secret for network devices |
| `PAM_ADMIN_USER` | secrets.env | No | Bootstrap admin username (default `admin`) |
| `PAM_ADMIN_PASS` | secrets.env | No | Bootstrap admin password (default `admin`) |
| `PAM_HTTP_PORT` | .env | No | Host port for UI (default `8080`) |
| `PAM_SSH_PORT` | .env | No | Host port for SSH proxy (default `2222`) |
| `PAM_TACACS_PORT` | .env | No | Host port for TACACS+ (default `49`) |
| `PAM_PORTAL_URL` | .env | No | Public URL of the portal (used in viewer links) |

Generate secrets:

```bash
openssl rand -hex 32       # PAM_JWT_SECRET, PAM_TACACS_SECRET
openssl rand -base64 32    # PAM_MASTER_KEY
```

> **Tip:** `.env` is only used by Docker Compose for `${VAR}` substitution — its values do **not** reach the containers. Everything containers read at startup must live in `secrets.env`.

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
aaa authentication login LOCAL-TACACS-BOTH group PAM local
aaa authentication enable LOCAL-TACACS-BOTH group PAM local enable
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

Secrets were in `deploy/docker/.env`. Compose treats `$name` inside `.env` as a variable reference and corrupts passwords that contain `$`.

**Fix:** move secrets to `secrets.env` (Compose does not expand `$` in env_file values):

```bash
cd /opt/lkpam
git pull origin main
cp deploy/docker/secrets.env.example deploy/docker/secrets.env

# Copy your existing secrets from .env into secrets.env, then REMOVE them from .env:
#   PAM_JWT_SECRET, PAM_MASTER_KEY, PAM_TACACS_SECRET, PAM_ADMIN_PASS
nano deploy/docker/secrets.env
nano deploy/docker/.env

docker compose -f deploy/docker/docker-compose.yml up -d --build
```

`.env` should only contain ports/URLs (see `.env.example`). All passwords go in `secrets.env`.

**TACACS container missing (`ps tacacs` shows empty)**

Pull latest code (TACACS is included by default), then rebuild:

```bash
git pull origin main
docker compose -f deploy/docker/docker-compose.yml up -d --build tacacs
docker compose -f deploy/docker/docker-compose.yml logs tacacs --tail 20
```

Expect: `tacacs+ listening on :49`

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

**Browser SSH: “Tunnel error” / guacd Permission denied on recordings**

The `guacd` image runs as user `guacd`; PAM must not `chown` the shared
`pam-rec` volume to `pam` only. After `git pull`, recreate services and fix
permissions once as root:

```bash
cd /opt/lkpam && git pull
docker compose -f deploy/docker/docker-compose.yml up -d --force-recreate guacd rdp-proxy gateway auth vault policy approval audit ssh-proxy
docker compose -f deploy/docker/docker-compose.yml exec -u 0 guacd sh -c 'chmod -R 0777 /recordings && ls -la /recordings'
docker logs pam-guacd --tail 3   # expect: guacd-entrypoint: /recordings permissions set
docker logs pam-rdp-proxy --tail 2   # expect: browser-ssh=direct-target
```

Check rdp-proxy can reach guacd (8086 is internal only):

```bash
docker exec pam-rdp-proxy wget -qO- http://127.0.0.1:8086/health/deps
```

On connect, `docker logs pam-rdp-proxy --tail 5` should show
`→ <target-host>:22 as <privileged-user>`. Link a **privileged account** to
the target in the UI. Ensure the target allows SSH from the PAM host IP.

Do not set `PAM_BROWSER_SSH_VIA_PROXY=true` unless you intentionally route
browser SSH through `ssh-proxy` (default is direct from guacd to target).

## Production notes

This compose file is suitable for **dev / lab / PoC**. Before production:

- Replace SQLite with Postgres (shared `PAM_DB` DSN)
- Set strong `PAM_JWT_SECRET` and `PAM_MASTER_KEY`
- Change default admin password immediately
- Put TLS in front of port 8080 (nginx, Traefik, cloud LB)
- Do not expose internal service ports
