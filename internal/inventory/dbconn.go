package inventory

import "strings"

// Native database wire-protocol connection types (brokered via db-proxy).
const (
	ConnPostgres = "postgres"
	ConnMySQL    = "mysql"
	ConnMariaDB  = "mariadb"
	ConnMSSQL    = "mssql"
	ConnMongoDB  = "mongodb"
	ConnRedis    = "redis"
	ConnOracle   = "oracle"
)

// DatabaseConnectionTypes lists connection_type values routed through db-proxy.
var DatabaseConnectionTypes = []string{
	ConnPostgres, ConnMySQL, ConnMariaDB, ConnMSSQL, ConnMongoDB, ConnRedis, ConnOracle,
}

// IsDatabaseConnection reports whether connType uses the DB broker data plane.
func IsDatabaseConnection(connType string) bool {
	switch strings.ToLower(strings.TrimSpace(connType)) {
	case ConnPostgres, ConnMySQL, ConnMariaDB, ConnMSSQL, ConnMongoDB, ConnRedis, ConnOracle:
		return true
	default:
		return false
	}
}

// DatabaseEngine normalizes connection_type / kind to an engine slug for brokers.
func DatabaseEngine(connType, kind string) string {
	ct := strings.ToLower(strings.TrimSpace(connType))
	if IsDatabaseConnection(ct) {
		if ct == ConnMariaDB {
			return ConnMySQL
		}
		return ct
	}
	k := strings.ToLower(strings.TrimSpace(kind))
	switch {
	case strings.Contains(k, "postgres"):
		return ConnPostgres
	case strings.Contains(k, "mysql"), strings.Contains(k, "mariadb"):
		return ConnMySQL
	case strings.Contains(k, "mssql"), strings.Contains(k, "sqlserver"):
		return ConnMSSQL
	case strings.Contains(k, "mongo"):
		return ConnMongoDB
	case strings.Contains(k, "redis"):
		return ConnRedis
	case strings.Contains(k, "oracle"):
		return ConnOracle
	}
	return ""
}
