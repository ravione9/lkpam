package radius

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/example/pam-platform/internal/db"
)

// ClientRecord is one row in radius_clients — a NAS allowed to authenticate
// against this server, with its own shared secret.
type ClientRecord struct {
	ID                 int64
	Name               string
	NASIP              string // exact IP or CIDR
	Secret             []byte
	RequireMessageAuth bool
	Vendor             string // override of target.kind detection
	Disabled           bool
}

// ClientStore caches radius_clients with a short TTL so the server isn't
// hammering SQLite on every Access-Request. Refresh() is called from the
// handler when it sees a NAS it hasn't cached.
type ClientStore struct {
	DB            *db.DB
	DefaultSecret []byte // global fallback (PAM_RADIUS_SECRET)

	mu      sync.RWMutex
	exact   map[string]ClientRecord
	cidrs   []cidrRecord
	loaded  time.Time
	ttl     time.Duration
}

type cidrRecord struct {
	net   *net.IPNet
	rec   ClientRecord
}

// NewClientStore returns a store with a 30-second cache TTL. Pass an empty
// default secret to forbid clients without a DB row.
func NewClientStore(d *db.DB, defaultSecret []byte) *ClientStore {
	return &ClientStore{
		DB:            d,
		DefaultSecret: defaultSecret,
		ttl:           30 * time.Second,
	}
}

// Lookup returns the ClientRecord that covers the given NAS IP. Returns a
// synthetic record carrying the global default secret when no DB row matches
// (so the server keeps working out-of-the-box for single-secret deployments).
// Returns ErrUnknownClient if neither a row nor a default secret is configured.
func (c *ClientStore) Lookup(ctx context.Context, nasAddr string) (ClientRecord, error) {
	nasIP := hostFromAddr(nasAddr)
	if nasIP == "" {
		return ClientRecord{}, errors.New("radius: empty NAS address")
	}
	if err := c.refreshIfStale(ctx); err != nil {
		// stale cache is still usable
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if rec, ok := c.exact[nasIP]; ok {
		if rec.Disabled {
			return ClientRecord{}, ErrClientDisabled
		}
		return rec, nil
	}
	ip := net.ParseIP(nasIP)
	for _, cr := range c.cidrs {
		if cr.net != nil && ip != nil && cr.net.Contains(ip) {
			if cr.rec.Disabled {
				return ClientRecord{}, ErrClientDisabled
			}
			return cr.rec, nil
		}
	}
	if len(c.DefaultSecret) > 0 {
		return ClientRecord{
			NASIP:              nasIP,
			Secret:             c.DefaultSecret,
			RequireMessageAuth: false, // global default secret stays lenient
			Name:               "default",
		}, nil
	}
	return ClientRecord{}, ErrUnknownClient
}

// Errors returned by Lookup.
var (
	ErrUnknownClient  = errors.New("radius: no shared secret for NAS")
	ErrClientDisabled = errors.New("radius: NAS marked disabled")
)

// Refresh forces a reload of radius_clients from the DB.
func (c *ClientStore) Refresh(ctx context.Context) error {
	if c.DB == nil {
		return nil
	}
	rows, err := c.DB.QueryContext(ctx, `
		SELECT id, COALESCE(name,''), nas_ip, secret,
		       require_message_auth, COALESCE(vendor,''), disabled
		FROM radius_clients`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	defer rows.Close()
	exact := make(map[string]ClientRecord)
	var cidrs []cidrRecord
	for rows.Next() {
		var (
			rec     ClientRecord
			needMA  int
			disable int
			secret  string
		)
		if err := rows.Scan(&rec.ID, &rec.Name, &rec.NASIP, &secret,
			&needMA, &rec.Vendor, &disable); err != nil {
			return err
		}
		rec.Secret = []byte(secret)
		rec.RequireMessageAuth = needMA != 0
		rec.Disabled = disable != 0
		if strings.Contains(rec.NASIP, "/") {
			if _, n, err := net.ParseCIDR(rec.NASIP); err == nil {
				cidrs = append(cidrs, cidrRecord{net: n, rec: rec})
			}
			continue
		}
		exact[rec.NASIP] = rec
	}
	if err := rows.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.exact = exact
	c.cidrs = cidrs
	c.loaded = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *ClientStore) refreshIfStale(ctx context.Context) error {
	c.mu.RLock()
	stale := time.Since(c.loaded) > c.ttl
	empty := c.exact == nil
	c.mu.RUnlock()
	if !stale && !empty {
		return nil
	}
	return c.Refresh(ctx)
}

func hostFromAddr(addrPort string) string {
	if i := strings.LastIndex(addrPort, ":"); i >= 0 {
		return strings.TrimSpace(addrPort[:i])
	}
	return strings.TrimSpace(addrPort)
}
