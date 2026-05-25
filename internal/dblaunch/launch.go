// Package dblaunch handles policy-checked, brokered database sessions.
// Users never receive standing DB passwords — PAM checks out credentials from
// the vault and the db-proxy relays wire-protocol traffic with audit.
package dblaunch

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/accounts"
	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/inventory"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/sessions"
	"github.com/example/pam-platform/internal/vault"
)

var (
	ErrTargetNotFound   = errors.New("target not found")
	ErrNotDatabase      = errors.New("target is not a database connection")
	ErrPolicyDenied     = errors.New("access denied by policy")
	ErrApprovalRequired = errors.New("approved access request required — submit a request and wait for approval")
	ErrNoAccount        = errors.New("no privileged account linked — admin must add a DB account in Safes")
)

// LaunchResult is returned when a user starts a brokered DB session.
type LaunchResult struct {
	SessionID       string `json:"session_id"`
	TargetName      string `json:"target_name"`
	Engine          string `json:"engine"`
	Database        string `json:"database"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	BrokerHost      string `json:"broker_host"`
	BrokerPort      int    `json:"broker_port"`
	ConnectionUser  string `json:"connection_user"`
	ConnectionToken string `json:"connection_token"`
	ConnectionURI   string `json:"connection_uri"`
	Instructions    string `json:"instructions"`
	Recorded        bool   `json:"recorded"`
	HasAccount      bool   `json:"has_account"`
}

// Service wires policy, approval, accounts, and vault for DB targets.
type Service struct {
	DB          *db.DB
	Policy      *policy.Engine
	Approval    *approval.Service
	Groups      *groups.Service
	Accounts    *accounts.Service
	Vault       *vault.Vault
	BrokerHost  string
	BrokerPorts map[string]int // engine -> listen port
}

// SessionSecretName returns the vault key for a DB session payload.
func SessionSecretName(sessionID string) string {
	return sessions.DBVaultSecretName(sessionID)
}

// SessionCreds is stored in the vault for db-proxy to load at connect time.
type SessionCreds struct {
	Engine         string `json:"engine"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Database       string `json:"database"`
	BrokerToken    string `json:"broker_token"`
	PortalUser     string `json:"portal_user"`
	PortalUserID   int64  `json:"portal_user_id"`
	TargetID       int64  `json:"target_id"`
	TargetKind     string `json:"target_kind"`
}

// Launch authorises the caller and creates a recorded DB broker session.
func (s *Service) Launch(ctx context.Context, targetID, userID int64, userRole, portalUsername, reason, clientIP string) (*LaunchResult, error) {
	var (
		name, kind, connType, host, dbName string
		port, tier                         int
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT name, kind, COALESCE(connection_type,'ssh'), host, port, tier,
		       COALESCE(db_name,'')
		FROM targets WHERE id = ?`, targetID).
		Scan(&name, &kind, &connType, &host, &port, &tier, &dbName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTargetNotFound
		}
		return nil, err
	}
	if !inventory.IsDatabaseConnection(connType) {
		return nil, ErrNotDatabase
	}
	if host == "" {
		return nil, errors.New("database host is required")
	}
	engine := inventory.DatabaseEngine(connType, kind)
	if engine == "" {
		engine = connType
	}
	if port <= 0 {
		port = defaultEnginePort(engine)
	}
	if dbName == "" {
		dbName = defaultDatabase(engine)
	}

	roles, err := s.Groups.EffectiveRoles(ctx, userID, userRole)
	if err != nil {
		return nil, err
	}
	dec, err := s.Policy.Decide(ctx, policy.Input{
		UserID: userID, Role: userRole, Roles: roles,
		TargetID: targetID, TargetKind: kind, TargetTier: tier, Action: "ssh",
	})
	if err != nil {
		return nil, err
	}
	if !dec.Allow {
		return nil, fmt.Errorf("%w: %v", ErrPolicyDenied, dec.Reasons)
	}
	if dec.RequireApproval {
		ok, err := s.Approval.IsApproved(ctx, userID, targetID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrApprovalRequired
		}
	}

	_ = sessions.EndActiveForUserTarget(ctx, s.DB, s.Vault, userID, targetID, "db", "superseded")

	acct, dualControl, err := s.Accounts.FindAccountForTarget(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if dualControl {
		ok, err := s.Approval.IsApproved(ctx, userID, targetID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrApprovalRequired
		}
	}
	co, err := s.Accounts.Checkout(ctx, acct.ID, userID, reason, false)
	if err != nil {
		return nil, fmt.Errorf("checkout DB account: %w", err)
	}
	pw := co.Password

	sessionID := fmt.Sprintf("db-%d-%d", time.Now().UnixNano(), targetID)
	brokerToken, err := randomToken(32)
	if err != nil {
		return nil, err
	}

	creds := SessionCreds{
		Engine:       engine,
		Username:     acct.Username,
		Password:     pw,
		Host:         host,
		Port:         port,
		Database:     dbName,
		BrokerToken:  brokerToken,
		PortalUser:   strings.TrimSpace(portalUsername),
		PortalUserID: userID,
		TargetID:     targetID,
		TargetKind:   kind,
	}
	if err := storeSessionCreds(ctx, s.Vault, sessionID, creds); err != nil {
		return nil, err
	}

	if reason == "" {
		reason = "Database session via PAM broker"
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO sessions(id, user_id, target_id, started_at, client_ip, protocol, account_id)
		VALUES(?,?,?,?,?,'db',?)`,
		sessionID, userID, targetID, db.Now(), clientIP, acct.ID)
	if err != nil {
		_ = s.Vault.DeleteSecret(ctx, SessionSecretName(sessionID))
		return nil, err
	}

	brokerPort := s.BrokerPorts[engine]
	if brokerPort <= 0 {
		brokerPort = defaultBrokerPort(engine)
	}
	brokerHost := strings.TrimSpace(s.BrokerHost)
	if brokerHost == "" {
		brokerHost = "localhost"
	}
	connUser := "pam." + sessionID
	uri := connectionURI(engine, brokerHost, brokerPort, connUser, dbName)

	return &LaunchResult{
		SessionID:       sessionID,
		TargetName:      name,
		Engine:          engine,
		Database:        dbName,
		Host:            host,
		Port:            port,
		BrokerHost:      brokerHost,
		BrokerPort:      brokerPort,
		ConnectionUser:  connUser,
		ConnectionToken: brokerToken,
		ConnectionURI:   uri,
		Instructions:    instructions(engine, brokerHost, brokerPort),
		Recorded:        true,
		HasAccount:      true,
	}, nil
}

func storeSessionCreds(ctx context.Context, v *vault.Vault, sessionID string, c SessionCreds) error {
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%d\n%s\n%s\n%d\n%d\n%s\n%s",
		c.Engine, c.Username, c.Password, c.Host, c.Port, c.Database,
		c.BrokerToken, c.PortalUserID, c.TargetID, c.PortalUser, c.TargetKind)
	return v.PutSecret(ctx, SessionSecretName(sessionID), []byte(payload), nil)
}

// LoadSessionCreds reads broker session credentials from the vault.
func LoadSessionCreds(ctx context.Context, v *vault.Vault, sessionID string) (SessionCreds, error) {
	raw, err := v.GetSecret(ctx, SessionSecretName(sessionID))
	if err != nil {
		return SessionCreds{}, err
	}
	parts := strings.SplitN(string(raw), "\n", 11)
	c := SessionCreds{}
	if len(parts) > 0 {
		c.Engine = parts[0]
	}
	if len(parts) > 1 {
		c.Username = parts[1]
	}
	if len(parts) > 2 {
		c.Password = parts[2]
	}
	if len(parts) > 3 {
		c.Host = parts[3]
	}
	if len(parts) > 4 {
		fmt.Sscanf(parts[4], "%d", &c.Port)
	}
	if len(parts) > 5 {
		c.Database = parts[5]
	}
	if len(parts) > 6 {
		c.BrokerToken = parts[6]
	}
	if len(parts) > 7 {
		fmt.Sscanf(parts[7], "%d", &c.PortalUserID)
	}
	if len(parts) > 8 {
		fmt.Sscanf(parts[8], "%d", &c.TargetID)
	}
	if len(parts) > 9 {
		c.PortalUser = parts[9]
	}
	if len(parts) > 10 {
		c.TargetKind = parts[10]
	}
	return c, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func defaultEnginePort(engine string) int {
	switch engine {
	case inventory.ConnPostgres:
		return 5432
	case inventory.ConnMySQL, inventory.ConnMariaDB:
		return 3306
	case inventory.ConnMSSQL:
		return 1433
	case inventory.ConnMongoDB:
		return 27017
	case inventory.ConnRedis:
		return 6379
	case inventory.ConnOracle:
		return 1521
	default:
		return 5432
	}
}

func defaultBrokerPort(engine string) int {
	switch engine {
	case inventory.ConnPostgres:
		return 15432
	case inventory.ConnMySQL, inventory.ConnMariaDB:
		return 13306
	case inventory.ConnMSSQL:
		return 11433
	case inventory.ConnMongoDB:
		return 27018
	case inventory.ConnRedis:
		return 16379
	case inventory.ConnOracle:
		return 11521
	default:
		return 15432
	}
}

func defaultDatabase(engine string) string {
	switch engine {
	case inventory.ConnPostgres:
		return "postgres"
	case inventory.ConnMySQL, inventory.ConnMariaDB:
		return "mysql"
	case inventory.ConnMSSQL:
		return "master"
	case inventory.ConnMongoDB:
		return "admin"
	case inventory.ConnRedis:
		return "0"
	default:
		return ""
	}
}

func connectionURI(engine, host string, port int, user, dbName string) string {
	switch engine {
	case inventory.ConnPostgres:
		return fmt.Sprintf("postgresql://%s@%s:%d/%s", user, host, port, dbName)
	case inventory.ConnMySQL, inventory.ConnMariaDB:
		return fmt.Sprintf("mysql://%s@%s:%d/%s", user, host, port, dbName)
	case inventory.ConnRedis:
		return fmt.Sprintf("redis://%s@%s:%d/%d", user, host, port, 0)
	default:
		return fmt.Sprintf("%s://%s@%s:%d/%s", engine, user, host, port, dbName)
	}
}

func instructions(engine, brokerHost string, brokerPort int) string {
	switch engine {
	case inventory.ConnPostgres:
		return fmt.Sprintf("Connect with psql to %s:%d using the broker username and one-time token as password. Traffic is relayed through PAM — the real DB password never leaves the vault.", brokerHost, brokerPort)
	case inventory.ConnMySQL, inventory.ConnMariaDB:
		return fmt.Sprintf("Connect with mysql client to %s:%d using the broker username and one-time token. All queries are audited.", brokerHost, brokerPort)
	case inventory.ConnRedis:
		return fmt.Sprintf("Connect redis-cli to %s:%d with AUTH using the broker token.", brokerHost, brokerPort)
	default:
		return fmt.Sprintf("Connect your %s client to PAM broker %s:%d — credentials are short-lived and session-scoped.", engine, brokerHost, brokerPort)
	}
}
