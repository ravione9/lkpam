package radius

import (
	"context"
	"crypto/md5"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
)

// captureBus collects events for assertion in tests.
type captureBus struct {
	mu     sync.Mutex
	events []events.Event
}

func (c *captureBus) Publish(ev events.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}
func (c *captureBus) Subscribe() <-chan events.Event { return nil }

func (c *captureBus) findKind(kind string) *events.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.events {
		if c.events[i].Kind == kind {
			return &c.events[i]
		}
	}
	return nil
}

func seedUser(t *testing.T, d *db.DB, user, pass string) {
	t.Helper()
	hash, err := cryptox.PasswordHash(pass)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := d.Exec(`
		INSERT INTO users(username,email,password_hash,role,source,created_at,disabled)
		VALUES(?,?,?,?,?,?,0)`,
		user, user+"@example.com", hash, "admin", "local", 1234); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func startServer(t *testing.T, bus events.Publisher, d *db.DB) (authAddr, acctAddr string, stop func()) {
	t.Helper()
	store := NewClientStore(d, []byte("test-secret"))
	srv := &Server{
		AuthAddr: "127.0.0.1:0",
		AcctAddr: "127.0.0.1:0",
		Clients:  store,
		DB:       d,
		Bus:      bus,
	}
	// We can't easily get the random port from Run, so listen ourselves and
	// hand the sockets to the loop.
	authConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen auth: %v", err)
	}
	acctConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen acct: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Eager refresh so handlers can resolve the default secret synchronously.
	if err := store.Refresh(ctx); err != nil {
		t.Fatalf("client refresh: %v", err)
	}
	// Make sure server defaults are applied (Run normally does this).
	srv.MaxPacketSize = MaxPacketLen
	srv.ReadTimeout = 5 * time.Second

	go func() { _ = srv.serveLoop(ctx, authConn, srv.handleAuth) }()
	go func() { _ = srv.serveLoop(ctx, acctConn, srv.handleAcct) }()

	stop = func() {
		cancel()
		_ = authConn.Close()
		_ = acctConn.Close()
	}
	return authConn.LocalAddr().String(), acctConn.LocalAddr().String(), stop
}

func sendAndRecv(t *testing.T, target string, payload []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", target)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return buf[:n]
}

func TestAccessRequestPAPSuccess(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	seedUser(t, d, "alice", "hunter2")

	bus := &captureBus{}
	authAddr, _, stop := startServer(t, bus, d)
	defer stop()

	secret := []byte("test-secret")
	req := &Packet{Code: CodeAccessRequest, Identifier: 7}
	for i := range req.Authenticator {
		req.Authenticator[i] = byte(i + 100)
	}
	req.Attrs.AddString(AttrUserName, "alice")
	req.Attrs.Add(AttrUserPassword, EncodeUserPassword("hunter2", req.Authenticator[:], secret))
	wire, err := Encode(req, secret, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	reply := sendAndRecv(t, authAddr, wire)

	rp, err := Decode(reply, secret)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if rp.Code != CodeAccessAccept {
		t.Fatalf("got code=%d, want Access-Accept (2). reply=%v", rp.Code, rp)
	}
	if ev := bus.findKind("authen"); ev == nil || ev.Severity != "info" {
		t.Fatalf("expected info authen event, got %+v", bus.events)
	}
}

func TestAccessRequestPAPWrongPassword(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	seedUser(t, d, "alice", "hunter2")

	bus := &captureBus{}
	authAddr, _, stop := startServer(t, bus, d)
	defer stop()

	secret := []byte("test-secret")
	req := &Packet{Code: CodeAccessRequest, Identifier: 9}
	for i := range req.Authenticator {
		req.Authenticator[i] = byte(i + 50)
	}
	req.Attrs.AddString(AttrUserName, "alice")
	req.Attrs.Add(AttrUserPassword, EncodeUserPassword("WRONG", req.Authenticator[:], secret))
	wire, _ := Encode(req, secret, nil)
	reply := sendAndRecv(t, authAddr, wire)
	rp, err := Decode(reply, secret)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if rp.Code != CodeAccessReject {
		t.Fatalf("expected Access-Reject, got %d", rp.Code)
	}
	if msg := string(rp.Attrs.Get(AttrReplyMessage)); !strings.Contains(strings.ToLower(msg), "auth") {
		t.Fatalf("reject reason missing: %q", msg)
	}
}

func TestAccessRequestUnknownUserRejected(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	bus := &captureBus{}
	authAddr, _, stop := startServer(t, bus, d)
	defer stop()

	secret := []byte("test-secret")
	req := &Packet{Code: CodeAccessRequest, Identifier: 1}
	for i := range req.Authenticator {
		req.Authenticator[i] = byte(i + 200)
	}
	req.Attrs.AddString(AttrUserName, "ghost")
	req.Attrs.Add(AttrUserPassword, EncodeUserPassword("whatever", req.Authenticator[:], secret))
	wire, _ := Encode(req, secret, nil)
	reply := sendAndRecv(t, authAddr, wire)
	rp, err := Decode(reply, secret)
	if err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	// Default server config rejects unknown users (UnknownUserReject=false here).
	if rp.Code != CodeAccessReject {
		t.Fatalf("expected Access-Reject for unknown user, got %d", rp.Code)
	}
}

func TestAccountingRoundTrip(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	bus := &captureBus{}
	_, acctAddr, stop := startServer(t, bus, d)
	defer stop()

	secret := []byte("test-secret")
	pkt := &Packet{
		Code:       CodeAccountingRequest,
		Identifier: 3,
	}
	pkt.Attrs.AddString(AttrUserName, "bob")
	pkt.Attrs.AddUint32(AttrAcctStatusType, AcctStatusStart)
	pkt.Attrs.AddString(AttrAcctSessionID, "ABC123")

	// Accounting requires the Request Authenticator to be the MD5 over the
	// packet with auth=0 + secret. Build a wire packet, then re-stamp it.
	wire := buildAcctRequest(pkt, secret)
	reply := sendAndRecv(t, acctAddr, wire)
	rp, err := Decode(reply, secret)
	if err != nil {
		t.Fatalf("decode acct reply: %v", err)
	}
	if rp.Code != CodeAccountingResponse {
		t.Fatalf("expected Accounting-Response, got %d", rp.Code)
	}
	if ev := bus.findKind("acct.start"); ev == nil {
		t.Fatalf("expected acct.start event, got %+v", bus.events)
	}
}

// buildAcctRequest hand-stamps a valid Accounting-Request authenticator.
func buildAcctRequest(p *Packet, secret []byte) []byte {
	wire, _ := Encode(p, secret, nil)
	// blank authenticator
	for i := 4; i < HeaderLen; i++ {
		wire[i] = 0
	}
	// recompute authenticator = MD5(packet-with-zero-auth + secret)
	authBytes := append(append([]byte(nil), wire...), secret...)
	h := md5Sum(authBytes)
	copy(wire[4:HeaderLen], h)
	return wire
}

func md5Sum(b []byte) []byte {
	h := md5.Sum(b)
	return h[:]
}
