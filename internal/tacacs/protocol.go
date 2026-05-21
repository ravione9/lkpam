// Package tacacs implements (a useful subset of) the TACACS+ protocol as
// specified in RFC 8907. It is sufficient for AAA against Cisco IOS,
// IOS-XE, NX-OS, and Arista EOS in their default configurations.
//
// Coverage:
//   - Header parsing/serialization
//   - Body obfuscation with the shared secret (RFC 8907 §4.5)
//   - Authentication: ASCII login (START → REPLY GETPASS → CONTINUE → PASS/FAIL)
//   - Authorization: command authorization (AUTHOR REQUEST → REPLY PASS_ADD/FAIL)
//   - Accounting: START / WATCHDOG / STOP records
//
// Not covered yet:
//   - CHAP / MS-CHAP authentication (use PAP on FortiGate: set authen-type pap)
//   - Per-VRF binding
//   - Single-connection mode TLS (draft-ietf-opsawg-tacacs-tls)
//
// SECURITY: TACACS+ obfuscation is *not* encryption. In a real deployment,
// you tunnel the connection through your management network (out-of-band)
// or wrap it in IPsec/TLS. Always set a strong shared secret per device.
package tacacs

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocol constants (RFC 8907 §4.1).
const (
	Version             = 0xC0 // major=0xC, minor=0x0
	VersionMinorOne     = 0xC1 // some flows use minor=1

	TypeAuthentication uint8 = 0x01
	TypeAuthorization  uint8 = 0x02
	TypeAccounting     uint8 = 0x03

	FlagUnencrypted    uint8 = 0x01
	FlagSingleConnect  uint8 = 0x04

	HeaderLen = 12

	MaxBodyLen = 65535 // sanity cap; real packets are far smaller
)

// Authentication type codes (RFC 8907 §5.1).
const (
	AuthenTypeASCII = 1
	AuthenTypePAP   = 2
	AuthenTypeCHAP  = 3
)

// Authentication action codes.
const (
	AuthenActionLogin    uint8 = 0x01
	AuthenActionChPass   uint8 = 0x02
	AuthenActionSendAuth uint8 = 0x04
)

// Authentication reply statuses.
const (
	AuthenStatusPass    uint8 = 0x01
	AuthenStatusFail    uint8 = 0x02
	AuthenStatusGetData uint8 = 0x03
	AuthenStatusGetUser uint8 = 0x04
	AuthenStatusGetPass uint8 = 0x05
	AuthenStatusRestart uint8 = 0x06
	AuthenStatusError   uint8 = 0x07
)

// Authorization reply statuses.
const (
	AuthorStatusPassAdd  uint8 = 0x01
	AuthorStatusPassRepl uint8 = 0x02
	AuthorStatusFail     uint8 = 0x10
	AuthorStatusError    uint8 = 0x11
)

// Accounting flags.
const (
	AcctFlagStart    uint8 = 0x02
	AcctFlagStop     uint8 = 0x04
	AcctFlagWatchdog uint8 = 0x08
)

// Header is the 12-byte TACACS+ header.
type Header struct {
	Version  uint8
	Type     uint8
	SeqNo    uint8
	Flags    uint8
	SessID   uint32
	Length   uint32
}

// ReadHeader reads exactly 12 bytes and parses a Header.
func ReadHeader(r io.Reader) (Header, error) {
	var buf [HeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Header{}, err
	}
	h := Header{
		Version: buf[0],
		Type:    buf[1],
		SeqNo:   buf[2],
		Flags:   buf[3],
		SessID:  binary.BigEndian.Uint32(buf[4:8]),
		Length:  binary.BigEndian.Uint32(buf[8:12]),
	}
	if h.Length > MaxBodyLen {
		return h, fmt.Errorf("tacacs: body length %d exceeds cap", h.Length)
	}
	return h, nil
}

// Bytes serializes the header.
func (h Header) Bytes() []byte {
	var b [HeaderLen]byte
	b[0] = h.Version
	b[1] = h.Type
	b[2] = h.SeqNo
	b[3] = h.Flags
	binary.BigEndian.PutUint32(b[4:8], h.SessID)
	binary.BigEndian.PutUint32(b[8:12], h.Length)
	return b[:]
}

// obfuscate XOR-masks body in place using the MD5-derived keystream from
// RFC 8907 §4.5. The same function applies both directions.
func obfuscate(body []byte, h Header, secret []byte) {
	if h.Flags&FlagUnencrypted != 0 || len(secret) == 0 {
		return
	}
	stream := makeStream(h, secret, len(body))
	for i := range body {
		body[i] ^= stream[i]
	}
}

// makeStream produces the MD5 keystream described in RFC 8907.
func makeStream(h Header, secret []byte, n int) []byte {
	// MD5(session_id, key, version, seq_no) seeds the chain.
	out := make([]byte, 0, n+16)
	var prev []byte
	for len(out) < n {
		hasher := md5.New()
		var sid [4]byte
		binary.BigEndian.PutUint32(sid[:], h.SessID)
		hasher.Write(sid[:])
		hasher.Write(secret)
		hasher.Write([]byte{h.Version, h.SeqNo})
		if prev != nil {
			hasher.Write(prev)
		}
		prev = hasher.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// ReadBody reads h.Length bytes, deobfuscates in place, and returns them.
func ReadBody(r io.Reader, h Header, secret []byte) ([]byte, error) {
	if h.Length == 0 {
		return nil, nil
	}
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	obfuscate(body, h, secret)
	return body, nil
}

// WritePacket obfuscates body and writes the full packet.
func WritePacket(w io.Writer, h Header, body []byte, secret []byte) error {
	h.Length = uint32(len(body))
	if _, err := w.Write(h.Bytes()); err != nil {
		return err
	}
	cp := make([]byte, len(body))
	copy(cp, body)
	obfuscate(cp, h, secret)
	_, err := w.Write(cp)
	return err
}

// ---- Authentication body types ----

// AuthenStart is the AUTHEN START body (RFC 8907 §5.1).
type AuthenStart struct {
	Action        uint8
	PrivLvl       uint8
	AuthenType    uint8
	Service       uint8
	UserLen       uint8
	PortLen       uint8
	RemAddrLen    uint8
	DataLen       uint8
	User          string
	Port          string
	RemAddr       string
	Data          []byte
}

// ParseAuthenStart decodes the body.
func ParseAuthenStart(body []byte) (*AuthenStart, error) {
	if len(body) < 8 {
		return nil, errors.New("tacacs: authen start too short")
	}
	a := &AuthenStart{
		Action:     body[0],
		PrivLvl:    body[1],
		AuthenType: body[2],
		Service:    body[3],
		UserLen:    body[4],
		PortLen:    body[5],
		RemAddrLen: body[6],
		DataLen:    body[7],
	}
	off := 8
	if len(body) < off+int(a.UserLen)+int(a.PortLen)+int(a.RemAddrLen)+int(a.DataLen) {
		return nil, errors.New("tacacs: authen start truncated")
	}
	a.User = string(body[off : off+int(a.UserLen)])
	off += int(a.UserLen)
	a.Port = string(body[off : off+int(a.PortLen)])
	off += int(a.PortLen)
	a.RemAddr = string(body[off : off+int(a.RemAddrLen)])
	off += int(a.RemAddrLen)
	a.Data = append([]byte(nil), body[off:off+int(a.DataLen)]...)
	return a, nil
}

// AuthenReply is the server's reply (RFC 8907 §5.2).
type AuthenReply struct {
	Status    uint8
	Flags     uint8
	ServerMsg string
	Data      []byte
}

// Bytes serializes the reply.
func (r AuthenReply) Bytes() []byte {
	msg := []byte(r.ServerMsg)
	out := make([]byte, 6+len(msg)+len(r.Data))
	out[0] = r.Status
	out[1] = r.Flags
	binary.BigEndian.PutUint16(out[2:4], uint16(len(msg)))
	binary.BigEndian.PutUint16(out[4:6], uint16(len(r.Data)))
	copy(out[6:], msg)
	copy(out[6+len(msg):], r.Data)
	return out
}

// AuthenContinue is the client follow-up packet (RFC 8907 §5.3).
type AuthenContinue struct {
	UserMsg string
	Data    []byte
	Flags   uint8
}

// ParseAuthenContinue decodes.
func ParseAuthenContinue(body []byte) (*AuthenContinue, error) {
	if len(body) < 5 {
		return nil, errors.New("tacacs: authen continue too short")
	}
	msgLen := binary.BigEndian.Uint16(body[0:2])
	dataLen := binary.BigEndian.Uint16(body[2:4])
	flags := body[4]
	off := 5
	if len(body) < off+int(msgLen)+int(dataLen) {
		return nil, errors.New("tacacs: authen continue truncated")
	}
	return &AuthenContinue{
		UserMsg: string(body[off : off+int(msgLen)]),
		Data:    append([]byte(nil), body[off+int(msgLen):off+int(msgLen)+int(dataLen)]...),
		Flags:   flags,
	}, nil
}

// ---- Authorization body types ----

// AuthorRequest carries the user's command for per-cmd authorization.
type AuthorRequest struct {
	AuthenMethod uint8
	PrivLvl      uint8
	AuthenType   uint8
	AuthenService uint8
	User         string
	Port         string
	RemAddr      string
	Args         []string // "cmd=show", "cmd-arg=running-config", "service=shell", ...
}

// ParseAuthorRequest decodes (RFC 8907 §6.1).
func ParseAuthorRequest(body []byte) (*AuthorRequest, error) {
	if len(body) < 8 {
		return nil, errors.New("tacacs: author request too short")
	}
	a := &AuthorRequest{
		AuthenMethod:  body[0],
		PrivLvl:       body[1],
		AuthenType:    body[2],
		AuthenService: body[3],
	}
	uLen := int(body[4])
	pLen := int(body[5])
	rLen := int(body[6])
	argCnt := int(body[7])
	off := 8
	if len(body) < off+argCnt {
		return nil, errors.New("tacacs: author request: bad arg count")
	}
	argLens := make([]int, argCnt)
	for i := 0; i < argCnt; i++ {
		argLens[i] = int(body[off+i])
	}
	off += argCnt
	if len(body) < off+uLen+pLen+rLen {
		return nil, errors.New("tacacs: author request truncated user/port/rem")
	}
	a.User = string(body[off : off+uLen])
	off += uLen
	a.Port = string(body[off : off+pLen])
	off += pLen
	a.RemAddr = string(body[off : off+rLen])
	off += rLen
	for i := 0; i < argCnt; i++ {
		if len(body) < off+argLens[i] {
			return nil, errors.New("tacacs: author request truncated args")
		}
		a.Args = append(a.Args, string(body[off:off+argLens[i]]))
		off += argLens[i]
	}
	return a, nil
}

// AuthorReply is the server's authorization decision.
type AuthorReply struct {
	Status    uint8
	Args      []string
	ServerMsg string
	Data      []byte
}

// Bytes serializes.
func (r AuthorReply) Bytes() []byte {
	msg := []byte(r.ServerMsg)
	totalArgs := 0
	argBytes := make([][]byte, len(r.Args))
	for i, a := range r.Args {
		argBytes[i] = []byte(a)
		totalArgs += len(argBytes[i])
	}
	out := make([]byte, 6+len(r.Args)+totalArgs+len(msg)+len(r.Data))
	out[0] = r.Status
	out[1] = uint8(len(r.Args))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(msg)))
	binary.BigEndian.PutUint16(out[4:6], uint16(len(r.Data)))
	off := 6
	for i := range argBytes {
		out[off+i] = uint8(len(argBytes[i]))
	}
	off += len(r.Args)
	copy(out[off:], msg)
	off += len(msg)
	copy(out[off:], r.Data)
	off += len(r.Data)
	for _, a := range argBytes {
		copy(out[off:], a)
		off += len(a)
	}
	return out
}

// ---- Accounting body types ----

// AcctRequest is the accounting record.
type AcctRequest struct {
	Flags         uint8
	AuthenMethod  uint8
	PrivLvl       uint8
	AuthenType    uint8
	AuthenService uint8
	User          string
	Port          string
	RemAddr       string
	Args          []string
}

// ParseAcctRequest decodes.
func ParseAcctRequest(body []byte) (*AcctRequest, error) {
	if len(body) < 9 {
		return nil, errors.New("tacacs: acct request too short")
	}
	a := &AcctRequest{
		Flags:         body[0],
		AuthenMethod:  body[1],
		PrivLvl:       body[2],
		AuthenType:    body[3],
		AuthenService: body[4],
	}
	uLen := int(body[5])
	pLen := int(body[6])
	rLen := int(body[7])
	argCnt := int(body[8])
	off := 9
	argLens := make([]int, argCnt)
	for i := 0; i < argCnt; i++ {
		argLens[i] = int(body[off+i])
	}
	off += argCnt
	a.User = string(body[off : off+uLen])
	off += uLen
	a.Port = string(body[off : off+pLen])
	off += pLen
	a.RemAddr = string(body[off : off+rLen])
	off += rLen
	for i := 0; i < argCnt; i++ {
		a.Args = append(a.Args, string(body[off:off+argLens[i]]))
		off += argLens[i]
	}
	return a, nil
}

// AcctReply is the server's acknowledgement.
type AcctReply struct {
	Status    uint8
	ServerMsg string
	Data      []byte
}

// Bytes serializes.
func (r AcctReply) Bytes() []byte {
	msg := []byte(r.ServerMsg)
	out := make([]byte, 5+len(msg)+len(r.Data))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(r.Data)))
	out[4] = r.Status
	copy(out[5:], msg)
	copy(out[5+len(msg):], r.Data)
	return out
}
