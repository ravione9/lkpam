// Package dbproxy brokers database wire-protocol connections through PAM.
// Users connect to PAM with short-lived session credentials; the proxy
// validates the session, checks out upstream credentials from the vault,
// and relays traffic with query audit (Adaptive-style: share access, not secrets).
package dbproxy

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/vault"
)

// Server listens on per-engine TCP ports and brokers DB sessions.
type Server struct {
	Vault  *vault.Vault
	DB     *db.DB
	Bus    events.Publisher
	Ports  map[string]int // engine -> listen port, e.g. postgres -> 15432
}

// Run starts all engine listeners until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if len(s.Ports) == 0 {
		s.Ports = defaultPorts()
	}
	var wg sync.WaitGroup
	for engine, port := range s.Ports {
		ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", itoa(port)))
		if err != nil {
			return err
		}
		log.Printf("db-proxy: %s broker listening on :%d", engine, port)
		wg.Add(1)
		go func(engine string, ln net.Listener) {
			defer wg.Done()
			defer ln.Close()
			go func() {
				<-ctx.Done()
				ln.Close()
			}()
			for {
				c, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Printf("db-proxy accept: %v", err)
					continue
				}
				go s.handleConn(ctx, engine, c)
			}
		}(engine, ln)
	}
	<-ctx.Done()
	wg.Wait()
	return ctx.Err()
}

func (s *Server) handleConn(ctx context.Context, engine string, client net.Conn) {
	defer client.Close()
	switch engine {
	case "postgres":
		if err := s.servePostgres(ctx, client); err != nil {
			log.Printf("db-proxy postgres session: %v", err)
		}
	default:
		if err := s.serveGeneric(ctx, engine, client); err != nil {
			log.Printf("db-proxy %s session: %v", engine, err)
		}
	}
}

func defaultPorts() map[string]int {
	return map[string]int{
		"postgres": 15432,
		"mysql":    13306,
		"mssql":    11433,
		"mongodb":  27018,
		"redis":    16379,
		"oracle":   11521,
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
