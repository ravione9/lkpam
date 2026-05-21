// Package db is the persistence layer. It uses SQLite for the reference
// implementation; the schema is portable to PostgreSQL with minor edits.
//
// In production: replace with Postgres (lib/pq or pgx) and run migrations
// with golang-migrate. The interface here intentionally stays narrow so swap
// is mechanical.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB with PAM-specific helpers.
type DB struct {
	*sql.DB
}

// Open opens (and migrates) the database at the given DSN.
// Example DSN for sqlite: "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)"
func Open(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}
	sqlDB.SetMaxOpenConns(1) // sqlite likes single-writer
	if err := sqlDB.PingContext(context.Background()); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}
	d := &DB{sqlDB}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("db migrate: %w", err)
	}
	return d, nil
}

func (d *DB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			email TEXT,
			password_hash TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT 'user',
			mfa_secret TEXT,
			mfa_enabled INTEGER NOT NULL DEFAULT 0,
			source TEXT NOT NULL DEFAULT 'local',
			external_dn TEXT,
			last_login INTEGER,
			created_at INTEGER NOT NULL,
			disabled INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS targets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			kind TEXT NOT NULL,           -- linux | cisco | arista | juniper | palo | forti | windows
			host TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 22,
			tier INTEGER NOT NULL DEFAULT 2, -- 0=critical (approval required) ... 3=dev
			tags TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
			ciphertext TEXT NOT NULL,
			rotation_due INTEGER,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS policies (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			role TEXT NOT NULL,
			target_kind TEXT NOT NULL,    -- '*' or kind
			tier_max INTEGER NOT NULL,    -- highest tier role may reach
			require_approval INTEGER NOT NULL DEFAULT 0,
			allowed_commands TEXT NOT NULL DEFAULT '',
			denied_commands TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS access_requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id),
			target_id INTEGER NOT NULL REFERENCES targets(id),
			reason TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending', -- pending|approved|denied|expired
			approver_id INTEGER,
			created_at INTEGER NOT NULL,
			decided_at INTEGER,
			ttl_seconds INTEGER NOT NULL DEFAULT 1800
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,           -- uuid-ish
			user_id INTEGER NOT NULL,
			target_id INTEGER NOT NULL,
			started_at INTEGER NOT NULL,
			ended_at INTEGER,
			recording_path TEXT,
			client_ip TEXT,
			ended_reason TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts INTEGER NOT NULL,
			actor TEXT NOT NULL,
			kind TEXT NOT NULL,
			target TEXT,
			detail TEXT,
			severity TEXT NOT NULL DEFAULT 'info'
		)`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			role TEXT NOT NULL DEFAULT 'user',
			ldap_dn TEXT,
			source TEXT NOT NULL DEFAULT 'local',
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_groups (
			user_id INTEGER NOT NULL,
			group_id INTEGER NOT NULL,
			added_at INTEGER NOT NULL,
			PRIMARY KEY (user_id, group_id),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT '',
			updated_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS saml_sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS roles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			builtin INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS approval_matrix (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			target_kind TEXT NOT NULL DEFAULT '*',     -- '*' or kind
			tier_min INTEGER NOT NULL DEFAULT 0,        -- inclusive
			tier_max INTEGER NOT NULL DEFAULT 3,        -- inclusive
			required_approvals INTEGER NOT NULL DEFAULT 1,
			requester_group_ids TEXT NOT NULL DEFAULT '', -- CSV: requester groups (empty = any)
			approver_group_ids TEXT NOT NULL DEFAULT '', -- CSV of group ids
			priority INTEGER NOT NULL DEFAULT 100,      -- lower wins (most-specific)
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS approval_decisions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			request_id INTEGER NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
			approver_id INTEGER NOT NULL REFERENCES users(id),
			approve INTEGER NOT NULL,
			comment TEXT NOT NULL DEFAULT '',
			decided_at INTEGER NOT NULL,
			UNIQUE(request_id, approver_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, started_at)`,
		`CREATE TABLE IF NOT EXISTS safes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			cpm_enabled INTEGER NOT NULL DEFAULT 0,
			rotation_days INTEGER NOT NULL DEFAULT 90,
			require_dual_control INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS safe_members (
			safe_id INTEGER NOT NULL REFERENCES safes(id) ON DELETE CASCADE,
			principal_type TEXT NOT NULL,        -- 'user' | 'group'
			principal_id INTEGER NOT NULL,
			permissions TEXT NOT NULL DEFAULT 'use', -- 'owner' | 'use' | 'view'
			added_at INTEGER NOT NULL,
			PRIMARY KEY (safe_id, principal_type, principal_id)
		)`,
		`CREATE TABLE IF NOT EXISTS privileged_accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			safe_id INTEGER NOT NULL REFERENCES safes(id),
			name TEXT NOT NULL,
			username TEXT NOT NULL,
			target_id INTEGER REFERENCES targets(id),
			platform TEXT NOT NULL DEFAULT 'linux',
			secret_ref TEXT NOT NULL,            -- vault secret name
			last_rotated INTEGER,
			next_rotation INTEGER,
			rotation_status TEXT NOT NULL DEFAULT 'pending',
			rotation_error TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			UNIQUE(safe_id, name)
		)`,
		`CREATE TABLE IF NOT EXISTS rotation_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id INTEGER NOT NULL REFERENCES privileged_accounts(id) ON DELETE CASCADE,
			ts INTEGER NOT NULL,
			status TEXT NOT NULL,
			actor TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS credential_checkouts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_id INTEGER NOT NULL REFERENCES privileged_accounts(id),
			user_id INTEGER NOT NULL REFERENCES users(id),
			checked_out_at INTEGER NOT NULL,
			returned_at INTEGER,
			reason TEXT NOT NULL DEFAULT '',
			break_glass INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS app_credentials (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			api_key_hash TEXT NOT NULL,
			safe_id INTEGER REFERENCES safes(id),
			allowed_accounts TEXT NOT NULL DEFAULT '',  -- CSV of account ids, or '*'
			client_ip_allow TEXT NOT NULL DEFAULT '',   -- CSV of CIDRs
			enabled INTEGER NOT NULL DEFAULT 1,
			last_used INTEGER,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS threat_alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts INTEGER NOT NULL,
			user_id INTEGER,
			username TEXT NOT NULL DEFAULT '',
			category TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'info',
			message TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			acknowledged INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS session_terminations (
			session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
			requested_by INTEGER NOT NULL,
			requested_at INTEGER NOT NULL,
			reason TEXT NOT NULL DEFAULT '',
			acknowledged_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_user_groups_group ON user_groups(group_id)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_decisions_req ON approval_decisions(request_id)`,
		`CREATE INDEX IF NOT EXISTS idx_approval_matrix_target ON approval_matrix(target_kind, tier_min, tier_max)`,
		`CREATE INDEX IF NOT EXISTS idx_accounts_safe ON privileged_accounts(safe_id)`,
		`CREATE INDEX IF NOT EXISTS idx_accounts_next_rotation ON privileged_accounts(next_rotation)`,
		`CREATE INDEX IF NOT EXISTS idx_rotation_history_acct ON rotation_history(account_id, ts DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_checkouts_user ON credential_checkouts(user_id, checked_out_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_threat_ts ON threat_alerts(ts DESC)`,
	}
	for _, s := range stmts {
		if _, err := d.Exec(s); err != nil {
			return fmt.Errorf("migrate stmt %q: %w", s[:40], err)
		}
	}
	// Best-effort additive migrations for existing databases.
	for _, alter := range []string{
		`ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local'`,
		`ALTER TABLE users ADD COLUMN external_dn TEXT`,
		`ALTER TABLE users ADD COLUMN last_login INTEGER`,
		`ALTER TABLE targets ADD COLUMN connection_type TEXT NOT NULL DEFAULT 'ssh'`,
		`ALTER TABLE targets ADD COLUMN web_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE targets ADD COLUMN vendor TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE targets ADD COLUMN os_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN protocol TEXT NOT NULL DEFAULT 'ssh'`,
		`ALTER TABLE sessions ADD COLUMN account_id INTEGER REFERENCES privileged_accounts(id)`,
		`ALTER TABLE approval_matrix ADD COLUMN requester_group_ids TEXT NOT NULL DEFAULT ''`,
	} {
		_, _ = d.Exec(alter) // ignore "duplicate column" errors on new DBs
	}
	return nil
}

// Helpers used by multiple services.

// Now returns the current unix timestamp.
func Now() int64 { return time.Now().Unix() }
