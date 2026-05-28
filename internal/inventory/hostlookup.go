package inventory

import (
	"context"
	"database/sql"
	"net/url"
	"strings"

	"github.com/example/pam-platform/internal/db"
)

func hostPart(addr string) string {
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// HostFromWebURL extracts the hostname from a web_url value.
func HostFromWebURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// NormalizeTargetHost copies the web_url hostname into Host when Host is empty
// for web / https-api targets so TACACS NAS lookups work.
func NormalizeTargetHost(t *Target) {
	if t == nil || t.Host != "" {
		return
	}
	if t.ConnectionType != ConnWeb && t.ConnectionType != ConnAPI {
		return
	}
	if h := HostFromWebURL(t.WebURL); h != "" {
		t.Host = h
	}
}

const hostMatchSQL = `
	SELECT %s FROM targets
	WHERE lower(host) = ?
	   OR lower(web_url) GLOB '*://' || ? || '/*'
	   OR lower(web_url) GLOB '*://' || ? || ':*'
	   OR lower(web_url) GLOB '*://' || ?
	LIMIT 1`

// KindForHost returns the target kind when host matches targets.host or web_url.
func KindForHost(ctx context.Context, d *db.DB, hostOrAddr string) (string, error) {
	host := strings.ToLower(hostPart(hostOrAddr))
	if host == "" {
		return "", sql.ErrNoRows
	}
	var kind string
	err := d.QueryRowContext(ctx, fmtHostMatch("kind"), host, host, host, host).Scan(&kind)
	return kind, err
}

// TargetMetaForHost returns id, kind, tier for a NAS IP/hostname.
func TargetMetaForHost(ctx context.Context, d *db.DB, hostOrAddr string) (id int64, kind string, tier int, err error) {
	host := strings.ToLower(hostPart(hostOrAddr))
	if host == "" {
		return 0, "", 0, sql.ErrNoRows
	}
	err = d.QueryRowContext(ctx, fmtHostMatch("id, kind, tier"), host, host, host, host).
		Scan(&id, &kind, &tier)
	return
}

func fmtHostMatch(cols string) string {
	return strings.Replace(hostMatchSQL, "%s", cols, 1)
}
