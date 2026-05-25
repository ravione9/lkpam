package dbproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/dblaunch"
)

// servePostgres accepts a psql/libpq client, validates pam.{session} + token,
// then relays to the upstream PostgreSQL server with vault credentials.
func (s *Server) servePostgres(ctx context.Context, client net.Conn) error {
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	startup, err := readPacket(client)
	if err != nil {
		return err
	}
	if len(startup) >= 8 && binary.BigEndian.Uint32(startup[4:8]) == 80877103 {
		// SSLRequest — decline and read real startup.
		if _, err := client.Write([]byte("N")); err != nil {
			return err
		}
		startup, err = readPacket(client)
		if err != nil {
			return err
		}
	}
	sessionID, dbName, err := parsePostgresStartup(startup)
	if err != nil {
		return err
	}
	// Ask client for password (cleartext).
	if err := writeAuthCleartext(client); err != nil {
		return err
	}
	passPkt, err := readPacket(client)
	if err != nil {
		return err
	}
	token, err := parsePasswordMessage(passPkt)
	if err != nil {
		return err
	}
	creds, err := dblaunch.LoadSessionCreds(ctx, s.Vault, sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %w", err)
	}
	if creds.BrokerToken != token {
		return errors.New("invalid broker token")
	}
	if creds.Engine != "postgres" {
		return fmt.Errorf("session engine mismatch: %s", creds.Engine)
	}
	if dbName == "" {
		dbName = creds.Database
	}
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(creds.Host, itoa(creds.Port)), 10*time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	_ = client.SetDeadline(time.Time{})
	if err := writePostgresStartup(upstream, creds.Username, dbName); err != nil {
		return err
	}
	if err := relayPostgresAuth(client, upstream, creds.Password); err != nil {
		return err
	}
	log.Printf("db-proxy: postgres relay session=%s user=%s db=%s upstream=%s:%d",
		sessionID, creds.Username, dbName, creds.Host, creds.Port)
	return relayBidirectional(client, upstream)
}

func parsePostgresStartup(pkt []byte) (sessionID, database string, err error) {
	if len(pkt) < 9 {
		return "", "", errors.New("startup too short")
	}
	body := pkt[4:]
	if binary.BigEndian.Uint32(body[0:4]) != 196608 {
		return "", "", errors.New("unsupported protocol version")
	}
	kv := body[4:]
	for len(kv) > 0 {
		key, rest, ok := splitNull(kv)
		if !ok {
			break
		}
		val, rest2, ok := splitNull(rest)
		if !ok {
			break
		}
		kv = rest2
		switch key {
		case "user":
			sessionID = strings.TrimPrefix(val, "pam.")
		case "database":
			database = val
		}
	}
	if sessionID == "" {
		return "", "", errors.New("missing pam session user")
	}
	return sessionID, database, nil
}

func splitNull(b []byte) (string, []byte, bool) {
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	if i >= len(b) {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

func writeAuthCleartext(w io.Writer) error {
	// AuthenticationCleartextPassword (type 'R', length 8, auth type 3)
	return writePacket(w, []byte{0, 0, 0, 8, 'R', 0, 0, 0, 3})
}

func parsePasswordMessage(pkt []byte) (string, error) {
	if len(pkt) < 5 || pkt[4] != 'p' {
		return "", errors.New("expected password message")
	}
	pw, _, ok := splitNull(pkt[5:])
	if !ok {
		return "", errors.New("bad password packet")
	}
	return pw, nil
}

func writePostgresStartup(w io.Writer, user, database string) error {
	var params []byte
	params = appendKV(params, "user", user)
	if database != "" {
		params = appendKV(params, "database", database)
	}
	params = append(params, 0)
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[0:4], 196608)
	copy(body[4:], params)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(4+len(body)))
	return writePacket(w, append(hdr[:], body...))
}

func appendKV(b []byte, k, v string) []byte {
	b = append(b, k...)
	b = append(b, 0)
	b = append(b, v...)
	b = append(b, 0)
	return b
}

func relayPostgresAuth(client, upstream net.Conn, upstreamPassword string) error {
	for {
		pkt, err := readPacket(upstream)
		if err != nil {
			return err
		}
		if len(pkt) < 5 {
			return errors.New("short auth packet from upstream")
		}
		msgType := pkt[4]
		switch msgType {
		case 'R':
			authType := binary.BigEndian.Uint32(pkt[8:12])
			switch authType {
			case 0: // AuthenticationOk
				if err := writePacket(client, pkt); err != nil {
					return err
				}
				// Read ParameterStatus / BackendKeyData until ReadyForQuery
				for {
					p, err := readPacket(upstream)
					if err != nil {
						return err
					}
					if err := writePacket(client, p); err != nil {
						return err
					}
					if len(p) >= 5 && p[4] == 'Z' {
						return nil
					}
				}
			case 3: // cleartext
				if err := writePacket(upstream, passwordPacket(upstreamPassword)); err != nil {
					return err
				}
			case 5: // md5 — send cleartext as fallback (many servers accept SCRAM/clear on retry)
				if err := writePacket(upstream, passwordPacket(upstreamPassword)); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported upstream auth type %d", authType)
			}
		case 'E', 'N':
			_ = writePacket(client, pkt)
			return errors.New("upstream auth failed")
		default:
			if err := writePacket(client, pkt); err != nil {
				return err
			}
		}
	}
}

func passwordPacket(pw string) []byte {
	body := append([]byte{'p'}, pw...)
	body = append(body, 0)
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(4+len(body)))
	return append(hdr[:], body...)
}

func readPacket(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 4 {
		return nil, errors.New("invalid packet length")
	}
	buf := make([]byte, n)
	copy(buf, hdr[:])
	if _, err := io.ReadFull(r, buf[4:]); err != nil {
		return nil, err
	}
	return buf, nil
}

func writePacket(w io.Writer, pkt []byte) error {
	_, err := w.Write(pkt)
	return err
}

func relayBidirectional(a, b net.Conn) error {
	errCh := make(chan error, 2)
	go func() { errCh <- copyConn(a, b) }()
	go func() { errCh <- copyConn(b, a) }()
	err1 := <-errCh
	err2 := <-errCh
	if err1 != nil {
		return err1
	}
	return err2
}

func copyConn(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	if tcp, ok := dst.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	return err
}
