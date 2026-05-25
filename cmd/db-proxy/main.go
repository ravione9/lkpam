package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/dbproxy"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/vault"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("db-proxy: open db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("db-proxy: vault: %v", err)
	}

	ports := map[string]int{
		"postgres": envInt("PAM_DB_POSTGRES_PORT", 15432),
		"mysql":    envInt("PAM_DB_MYSQL_PORT", 13306),
		"mssql":    envInt("PAM_DB_MSSQL_PORT", 11433),
		"mongodb":  envInt("PAM_DB_MONGODB_PORT", 27018),
		"redis":    envInt("PAM_DB_REDIS_PORT", 16379),
		"oracle":   envInt("PAM_DB_ORACLE_PORT", 11521),
	}

	srv := &dbproxy.Server{
		Vault: v,
		DB:    d,
		Bus:   events.NewForwarder(events.New(), config.Get("PAM_AUDIT_URL", "http://audit:8085")),
		Ports: ports,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("db-proxy starting — broker ports postgres=%d mysql=%d redis=%d",
		ports["postgres"], ports["mysql"], ports["redis"])
	if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("db-proxy: %v", err)
	}
}

func envInt(key string, def int) int {
	v := config.Get(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
