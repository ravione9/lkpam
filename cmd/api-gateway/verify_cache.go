package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// JWT verification can become a single-point bottleneck for the entire UI:
// every gated API call performs a POST to auth-service /verify before the
// request reaches the actual backend. When auth-service has a network blip
// (container restart, Docker DNS hiccup, brief DB lock), every dashboard
// shows the raw Go error — Proxy Log and Session History go dark first
// because they auto-refresh on a timer.
//
// The cache below mitigates this in two ways:
//
//  1. A successful verify is cached for verifyCacheTTL (60s). Subsequent
//     calls with the same token reuse the cached claims without hitting
//     auth-service, so a single user clicking through tabs only consults
//     the auth-service ~once per minute instead of on every API call.
//
//  2. On a network-class error (DNS failure, connection refused, timeout),
//     we serve a stale cached entry for verifyStaleTTL (5min) so the UI
//     keeps working while ops fixes the deployment. Authentication-class
//     errors (401 / 403 from auth-service) are NOT served from stale —
//     those are real "your token is bad" responses.
//
// Security trade-off: a user disabled in auth-service still has access for
// up to verifyCacheTTL after the change. For the reference platform this is
// acceptable; production deployments that need instant revocation should
// shorten verifyCacheTTL or invalidate the cache explicitly on user-mgmt
// writes (TODO).

const (
	verifyCacheTTL     = 60 * time.Second
	verifyStaleTTL     = 5 * time.Minute
	verifyCacheMaxSize = 4096
	verifyCacheGCEvery = 5 * time.Minute
)

type verifyCacheEntry struct {
	claims *claims
	expiry time.Time
	// stale is the deadline beyond which even error-fallback should give up.
	stale time.Time
}

var (
	verifyCacheMu sync.RWMutex
	verifyCache   = make(map[string]verifyCacheEntry)
	verifyGCOnce  sync.Once
)

// verifyTokenCached wraps verifyToken with a short-TTL cache that survives
// auth-service network blips. It returns the same shape as verifyToken so
// the call site is unchanged.
func verifyTokenCached(ctx context.Context, authBase *url.URL, tok string) (*claims, int, error) {
	startVerifyCacheGC()

	key := verifyCacheKey(tok)
	now := time.Now()

	verifyCacheMu.RLock()
	entry, hit := verifyCache[key]
	verifyCacheMu.RUnlock()

	if hit && now.Before(entry.expiry) {
		return entry.claims, http.StatusOK, nil
	}

	c, status, err := verifyToken(ctx, authBase, tok)
	if err == nil && c != nil {
		verifyCachePut(key, c)
		return c, status, nil
	}

	// Auth-service produced a definitive answer (4xx) — do NOT mask it.
	// Only fall back to stale on transport-class failures.
	if err != nil && isTransportError(err) && hit && now.Before(entry.stale) {
		return entry.claims, http.StatusOK, nil
	}
	if err != nil {
		err = friendlyAuthError(err, authBase)
	}
	return c, status, err
}

func verifyCacheKey(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func verifyCachePut(key string, c *claims) {
	now := time.Now()
	verifyCacheMu.Lock()
	defer verifyCacheMu.Unlock()
	// Bound cache size — if we hit the cap, drop the oldest-expiring entries.
	if len(verifyCache) >= verifyCacheMaxSize {
		// Cheap eviction: drop a fraction of entries whose expiry is in the past.
		evicted := 0
		for k, v := range verifyCache {
			if v.expiry.Before(now) {
				delete(verifyCache, k)
				evicted++
				if evicted >= verifyCacheMaxSize/4 {
					break
				}
			}
		}
		// Still full? Fall back to clearing the whole thing — rare.
		if len(verifyCache) >= verifyCacheMaxSize {
			verifyCache = make(map[string]verifyCacheEntry, verifyCacheMaxSize)
		}
	}
	verifyCache[key] = verifyCacheEntry{
		claims: c,
		expiry: now.Add(verifyCacheTTL),
		stale:  now.Add(verifyStaleTTL),
	}
}

// invalidateVerifyCache drops every cached entry. Call this after operations
// that should propagate instantly: user disable, role change, password reset.
// Exposed as a package-level function so middleware can call it.
func invalidateVerifyCache() {
	verifyCacheMu.Lock()
	verifyCache = make(map[string]verifyCacheEntry, 64)
	verifyCacheMu.Unlock()
}

func startVerifyCacheGC() {
	verifyGCOnce.Do(func() {
		go func() {
			t := time.NewTicker(verifyCacheGCEvery)
			defer t.Stop()
			for range t.C {
				now := time.Now()
				verifyCacheMu.Lock()
				for k, v := range verifyCache {
					if v.stale.Before(now) {
						delete(verifyCache, k)
					}
				}
				verifyCacheMu.Unlock()
			}
		}()
	})
}

// isTransportError reports whether err is a network-layer failure rather than
// an authoritative 4xx/5xx response. We use this to decide whether stale-
// cache fallback is safe.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// http.DefaultClient surfaces transport errors as url.Error wrapping a net err.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return true
	}
	// Last resort: substring sniff for the typical Go transport phrases.
	s := strings.ToLower(err.Error())
	for _, phrase := range []string{
		"dial tcp", "no such host", "server misbehaving",
		"connection refused", "i/o timeout", "context deadline exceeded",
		"connection reset",
	} {
		if strings.Contains(s, phrase) {
			return true
		}
	}
	return false
}

// friendlyAuthError rewrites Go's raw transport error into something useful
// in a browser. The original error is still returned to the caller via the
// wrapped message so logs aren't worse off.
func friendlyAuthError(err error, authBase *url.URL) error {
	if err == nil {
		return nil
	}
	if !isTransportError(err) {
		return err
	}
	host := ""
	if authBase != nil {
		host = authBase.Host
	}
	return errors.New("authentication service unreachable (" + host +
		") — verify the auth container is running on the pam-net network and try again: " + err.Error())
}
