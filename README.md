# PAM Platform — Reference Implementation

A microservice-based Privileged Access Management platform written in Go.
This is a working foundational scaffold of the architecture: real auth, real
credential vault with envelope encryption, policy engine, JIT approval
workflow, SSH proxy with session recording, audit pipeline, and an admin web
UI.

> Status: reference build. The cryptography, SSH handling, and persistence
> are real and correct. The platform is **not** production-ready as shipped —
> see "production hardening" below.

## Architecture

```
┌────────────────────────── api-gateway :8080 ───────────────────────────┐
│  REST + embedded web UI · JWT-gated · reverse-proxies internal svcs    │
└──┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────┘
   ▼             ▼             ▼             ▼             ▼
 auth         vault         policy       approval        audit
 :8081        :8082         :8083         :8084          :8085

                    ┌───────────────────────────┐
                    │   ssh-proxy :2222         │
                    │   data plane              │
                    │   records every session   │
                    └─────────────┬─────────────┘
                                  ▼
                      target devices / servers

  ┌───────────────────────┐         ┌─────────────────────────────┐
  │  tacacs-service :49   │         │  radius-service             │
  │  (Cisco / Arista /    │         │  :1812 auth  :1813 acct     │
  │   NX-OS / FortiGate)  │         │  (HP / Aruba / MikroTik /   │
  │                       │         │   F5 / Palo Alto / Juniper) │
  └──────────┬────────────┘         └──────────┬──────────────────┘
             ▼                                 ▼
       network devices                    network devices
       (TCP/49 AAA)                       (UDP/1812 AAA, UDP/1813 acct)
```

* **auth-service** — Argon2id passwords, HS256 JWTs, MFA stub.
* **vault-service** — AES-256-GCM encrypted secrets, Ed25519 SSH CA, issues
  short-lived SSH certs.
* **policy-service** — RBAC + per-command allow/deny. OPA-ready (see
  `policies/example.rego`).
* **approval-service** — JIT access requests with TTL.
* **audit-service** — SQLite + JSONL append-only audit log; SIEM-ready.
* **ssh-proxy** — SSH server that accepts users, authorizes via policy,
  connects downstream with a cert, and records the session.
* **tacacs-service** — RFC 8907 TACACS+ AAA for Cisco / Arista / FortiGate.
* **radius-service** — RFC 2865/2866 RADIUS AAA for devices that don't speak
  TACACS+: HP / Aruba switches, MikroTik, F5, Palo Alto admin login, Juniper,
  Huawei, VPN concentrators, WLCs. Per-NAS shared secrets live in
  `radius_clients`; PAP / CHAP supported; vendor reply attributes (Cisco AV-pair,
  Juniper local-user-name, Fortinet-Group-Name, MikroTik-Group, etc.) are
  emitted automatically based on the target's `kind`.
* **api-gateway** — externally facing entry point with embedded admin UI.

## Quick start (local)

```bash
make build                  # builds all 8 binaries into ./bin
mkdir -p data recordings

# In separate terminals:
make run-auth
make run-vault
make run-policy
make run-approval
make run-audit
make run-ssh-proxy
make run-gateway

# Then open http://localhost:8080  (default credentials: admin / admin)
```

Or with Docker (recommended):

```bash
cp deploy/docker/.env.example deploy/docker/.env   # edit secrets
make docker-up                                      # build + start
# Admin UI: http://localhost:8080  (admin / admin)
# SSH:      ssh -p 2222 user@target-name@localhost
```

See [deploy/docker/README.md](deploy/docker/README.md) for full Docker deployment docs.

### Pointing network devices at the PAM RADIUS server

The RADIUS service exposes UDP/1812 (auth) and UDP/1813 (accounting). Add the
NAS to the `radius_clients` table (or rely on the global `PAM_RADIUS_SECRET`),
then configure the device. Examples:

```
! HP / Aruba ProCurve
radius-server host 10.20.30.40 key STRONG-SECRET
aaa authentication ssh login radius local
aaa accounting commands start-stop radius

! Cisco IOS (RADIUS path — use TACACS+ when available)
radius server PAM
 address ipv4 10.20.30.40 auth-port 1812 acct-port 1813
 key STRONG-SECRET
aaa authentication login default group radius local
aaa authorization exec default group radius local
aaa accounting exec default start-stop group radius

# MikroTik RouterOS
/radius add service=login address=10.20.30.40 secret=STRONG-SECRET
/user aaa set use-radius=yes default-group=read

# Palo Alto: Device > Server Profiles > RADIUS (1812, secret),
#            then Authentication Profile, then Administrators.
```

Per-device shared secrets live in the `radius_clients` table:

```sql
INSERT INTO radius_clients(name,nas_ip,secret,require_message_auth,vendor,disabled,created_at)
VALUES('core-sw-01','10.20.30.41','STRONG-PER-DEVICE-KEY',1,'aruba',0,strftime('%s','now'));
```

CIDR rows (`10.20.30.0/24`) onboard a whole VLAN under one secret.

## Trying it out

1. Sign in to the UI at <http://localhost:8080> with `admin / admin`.
2. Insert a target into the DB (use `sqlite3 data/pam.db`):
   ```sql
   INSERT INTO targets(name,kind,host,port,tier) VALUES('core-sw-01','cisco','192.168.1.1',22,1);
   ```
3. Try opening an SSH session through the proxy:
   ```bash
   ssh -p 2222 admin@core-sw-01@localhost
   ```
   The proxy parses `admin@core-sw-01` as "user=admin, target=core-sw-01",
   checks policy, issues a short-lived cert for the target, opens the
   downstream SSH, and records the entire session to `./recordings/`.
4. Check the audit tab in the UI to see the events.

## Project layout

```
pam-platform/
├── cmd/                     one main.go per service
├── internal/
│   ├── auth/                user, password, JWT
│   ├── vault/               AES-GCM secrets, SSH CA, cert issuance
│   ├── policy/              RBAC + command filtering
│   ├── approval/            JIT access workflow
│   ├── audit/               event sinks
│   ├── sshproxy/            SSH data plane + session recording
│   ├── cryptox/             AES-GCM, Argon2id, SSH CA primitives
│   ├── db/                  schema + migrations (SQLite, Postgres-portable)
│   ├── events/              in-process event bus (Kafka-replaceable)
│   ├── httpx/               JSON, logging, bearer-token middleware
│   └── config/              env config
├── policies/                example Rego bundle for OPA swap-in
├── deploy/
│   ├── docker/              Dockerfile + docker-compose
│   └── k8s/                 minimal Kubernetes manifests
├── go.mod
├── Makefile
└── README.md
```

## Configuration

All services read environment variables (see `internal/config`):

| Var | Default | Purpose |
|---|---|---|
| `PAM_DB` | `file:./data/pam.db?...` | SQLite DSN (or Postgres) |
| `PAM_JWT_SECRET` | `dev-only-change-me` | HS256 signing secret |
| `PAM_JWT_TTL` | `30m` | JWT lifetime |
| `PAM_MASTER_KEY` | (empty) | base64 32-byte vault master key |
| `PAM_REQUIRE_MFA` | `0` | enforce OTP step on login |
| `PAM_AUTH_ADDR` | `:8081` | auth-service listen addr |
| `PAM_VAULT_ADDR` | `:8082` | vault-service listen addr |
| `PAM_POLICY_ADDR` | `:8083` | policy-service listen addr |
| `PAM_APPROVAL_ADDR` | `:8084` | approval-service listen addr |
| `PAM_AUDIT_ADDR` | `:8085` | audit-service listen addr |
| `PAM_SSH_PROXY_ADDR` | `:2222` | SSH proxy listen addr |
| `PAM_GATEWAY_ADDR` | `:8080` | API gateway listen addr |
| `PAM_REC_DIR` | `./recordings` | where to write session recordings |
| `PAM_TACACS_ADDR` | `:49` | TACACS+ listen addr |
| `PAM_TACACS_SECRET` | `change-me` | TACACS+ shared secret |
| `PAM_RADIUS_AUTH_ADDR` | `:1812` | RADIUS authentication listen addr |
| `PAM_RADIUS_ACCT_ADDR` | `:1813` | RADIUS accounting listen addr |
| `PAM_RADIUS_SECRET` | `change-me` | RADIUS global fallback shared secret |
| `PAM_RADIUS_UNKNOWN_USER` | `reject` | `reject` or `drop` for unknown users |

## Production hardening

Before this becomes safe to run in production:

1. **Replace SQLite with Postgres** (HA via Patroni). The schema in
   `internal/db/db.go` is already Postgres-compatible; swap the driver.
2. **Replace HS256 JWTs with RS256/EdDSA** keys held in the vault, or
   federate through Azure AD/Okta and stop minting tokens locally.
3. **Wire the vault master key to an HSM** (PKCS#11 or AWS CloudHSM).
   `PAM_MASTER_KEY` should become a wrap-key reference, not the raw key.
4. **Pin target host keys.** The proxy currently uses
   `ssh.InsecureIgnoreHostKey`. Add a `host_keys` table and verify on
   connect; first-trust-on-use is acceptable, silent acceptance is not.
5. **Swap the in-process event bus** for Kafka or NATS — multiple consumers
   (SIEM, UEBA, recording indexer) become independent.
6. **Replace the policy engine with OPA**. The `policies/example.rego`
   bundle is the migration target.
7. **Add per-command authorization on the proxy** (parse the byte stream
   line-by-line, call `/cmd-check`, optionally inject a block).
8. **Replace the bearer-token / `localStorage` UI auth flow** with
   HttpOnly secure cookies + CSRF tokens.
9. ~~Add a TACACS+/RADIUS service~~ — done. `cmd/tacacs-service` (port 49)
   and `cmd/radius-service` (UDP 1812/1813) both consult the policy engine
   and auth-service. Per-NAS shared secrets for RADIUS live in the
   `radius_clients` table; the `PAM_RADIUS_SECRET` env var is the global
   fallback for any NAS without a per-device row. **Production todo:**
   layer RadSec (RFC 6614) on top of the RADIUS UDP listener — wrap the
   conn in TLS — and run TACACS+ behind a TLS-terminating proxy for
   transport encryption (TACACS+ obfuscation isn't encryption).
10. **Enable mTLS between every internal service** (Istio or manual certs).

## Running unit tests

```bash
make test
```

Tests are sparse in the reference build — please add coverage as you build
out the features above.

## License

MIT. Don't ship this as-is; treat it as a starting point.
