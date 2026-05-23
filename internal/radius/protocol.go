// Package radius implements a usable subset of the RADIUS protocol for
// privileged-access AAA against network devices that don't speak TACACS+:
// HP/Aruba switches, MikroTik, F5, Palo Alto admin login, older Cisco AAA,
// Juniper Junos, Huawei, most VPN concentrators and WLCs.
//
// Coverage:
//   - RFC 2865 Access-Request / Access-Accept / Access-Reject / Access-Challenge
//   - RFC 2865 §5.2 User-Password obfuscation (PAP)
//   - RFC 2865 §2.2 CHAP (CHAP-Password / CHAP-Challenge)
//   - RFC 3579 §3.2 Message-Authenticator HMAC-MD5
//   - RFC 2866 Accounting-Request / Accounting-Response
//   - RFC 2868 Tunnel attributes (passthrough for VPN concentrators)
//   - Vendor-Specific (type 26) for Cisco / Fortinet / Juniper / HP / Aruba /
//     MikroTik / PaloAlto / Huawei / F5 — see vsa.go
//
// Not covered: MS-CHAPv2 mutual auth replies (we authenticate via auth-service
// instead and accept/reject), EAP, dynamic-auth (CoA / Disconnect).
//
// SECURITY: RADIUS over UDP relies on the shared secret for integrity of replies
// and for the User-Password obfuscation, but the attribute body itself is in
// the clear. In production: enable Message-Authenticator on every NAS, use per-
// device secrets (see radius_clients table), and run RADIUS strictly over an
// out-of-band management network. RadSec (RFC 6614) is the proper fix and is
// straightforward to layer on top of this code by wrapping the conn in TLS.
package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet codes (RFC 2865 §3 + RFC 2866 §4).
const (
	CodeAccessRequest      uint8 = 1
	CodeAccessAccept       uint8 = 2
	CodeAccessReject       uint8 = 3
	CodeAccountingRequest  uint8 = 4
	CodeAccountingResponse uint8 = 5
	CodeAccessChallenge    uint8 = 11
	CodeStatusServer       uint8 = 12 // RFC 5997
	CodeStatusClient       uint8 = 13
)

// Header is the 20-byte fixed prefix of every RADIUS packet.
const (
	HeaderLen       = 20
	AuthenticatorLen = 16
	MinPacketLen    = HeaderLen     // attributes optional
	MaxPacketLen    = 4096          // RFC 2865 §3
)

// Packet is a decoded RADIUS message.
type Packet struct {
	Code          uint8
	Identifier    uint8
	Authenticator [AuthenticatorLen]byte
	Attrs         AttributeList
}

// Attribute is one TLV inside a packet. Vendor-Specific values keep the full
// VSA payload (including the leading 4-byte VendorID).
type Attribute struct {
	Type  uint8
	Value []byte
}

// AttributeList is an ordered collection — RADIUS allows multiple attributes
// of the same type (e.g. Cisco-AVPair) and order is significant for some
// vendors (FreeRADIUS retains insertion order; we do the same).
type AttributeList []Attribute

// Get returns the first attribute of the given type, or nil if absent.
func (a AttributeList) Get(t uint8) []byte {
	for _, x := range a {
		if x.Type == t {
			return x.Value
		}
	}
	return nil
}

// GetAll returns every value for the given attribute type.
func (a AttributeList) GetAll(t uint8) [][]byte {
	var out [][]byte
	for _, x := range a {
		if x.Type == t {
			out = append(out, x.Value)
		}
	}
	return out
}

// Add appends a TLV. Length is range-checked because a single attribute body
// must fit in a uint8 length field minus 2 bytes of header.
func (a *AttributeList) Add(t uint8, v []byte) {
	if len(v) > 253 {
		v = v[:253] // RFC 2865 §5: attribute value max 253 bytes
	}
	*a = append(*a, Attribute{Type: t, Value: append([]byte(nil), v...)})
}

// AddString is a convenience for text attributes (Filter-Id, Reply-Message, …).
func (a *AttributeList) AddString(t uint8, s string) { a.Add(t, []byte(s)) }

// AddUint32 encodes a 4-byte integer attribute (Service-Type, NAS-Port, …).
func (a *AttributeList) AddUint32(t uint8, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	a.Add(t, b[:])
}

// Decode parses one UDP datagram into a Packet. The caller must already have
// looked up the shared secret for this client — Decode validates the
// Message-Authenticator (when present) and the request-authenticator length,
// but the body is otherwise unverified at the protocol level.
func Decode(buf []byte, secret []byte) (*Packet, error) {
	if len(buf) < HeaderLen {
		return nil, fmt.Errorf("radius: packet %d bytes < %d-byte header", len(buf), HeaderLen)
	}
	length := int(binary.BigEndian.Uint16(buf[2:4]))
	if length < HeaderLen || length > MaxPacketLen || length > len(buf) {
		return nil, fmt.Errorf("radius: bad length field %d (buf=%d)", length, len(buf))
	}
	p := &Packet{
		Code:       buf[0],
		Identifier: buf[1],
	}
	copy(p.Authenticator[:], buf[4:HeaderLen])

	off := HeaderLen
	for off < length {
		if off+2 > length {
			return nil, errors.New("radius: truncated attribute header")
		}
		t := buf[off]
		l := int(buf[off+1])
		if l < 2 || off+l > length {
			return nil, fmt.Errorf("radius: bad attribute len=%d at off=%d", l, off)
		}
		v := append([]byte(nil), buf[off+2:off+l]...)
		p.Attrs = append(p.Attrs, Attribute{Type: t, Value: v})
		off += l
	}

	// Message-Authenticator (RFC 3579 §3.2) MUST be HMAC-MD5(secret) over the
	// packet with the Message-Authenticator zeroed out. We only verify it for
	// Access-Request; replies are checked elsewhere.
	if p.Code == CodeAccessRequest {
		if ma := p.Attrs.Get(AttrMessageAuthenticator); ma != nil {
			if !verifyMessageAuthenticator(buf[:length], ma, secret) {
				return nil, errors.New("radius: Message-Authenticator HMAC mismatch")
			}
		}
	}
	return p, nil
}

// Encode serializes p into a wire packet, signing Message-Authenticator
// (always added on Access-Accept/Reject/Challenge when secret != "" per RFC
// 5080 §2.1.1 best practice) and computing the Response Authenticator.
//
// For accounting replies the Request Authenticator is taken from reqAuth.
func Encode(p *Packet, secret []byte, reqAuth []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("radius: nil packet")
	}

	wantMA := false
	switch p.Code {
	case CodeAccessAccept, CodeAccessReject, CodeAccessChallenge:
		wantMA = len(secret) > 0
	}

	attrs := p.Attrs
	if wantMA && attrs.Get(AttrMessageAuthenticator) == nil {
		var zero [16]byte
		attrs = append(attrs, Attribute{Type: AttrMessageAuthenticator, Value: zero[:]})
	}

	bodyLen := 0
	for _, a := range attrs {
		bodyLen += 2 + len(a.Value)
	}
	total := HeaderLen + bodyLen
	if total > MaxPacketLen {
		return nil, fmt.Errorf("radius: packet %d bytes exceeds %d", total, MaxPacketLen)
	}

	out := make([]byte, total)
	out[0] = p.Code
	out[1] = p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	off := HeaderLen
	for _, a := range attrs {
		out[off] = a.Type
		out[off+1] = uint8(2 + len(a.Value))
		copy(out[off+2:], a.Value)
		off += 2 + len(a.Value)
	}

	// Step 1: stamp Message-Authenticator (HMAC-MD5(secret) over packet with
	// MA=zero and ResponseAuth=request-authenticator). We assume reqAuth has
	// already been copied into out[4:20] for replies.
	if len(reqAuth) == AuthenticatorLen {
		copy(out[4:HeaderLen], reqAuth)
	} else if p.Code == CodeAccessRequest {
		copy(out[4:HeaderLen], p.Authenticator[:])
	}
	if wantMA {
		// Locate MA attribute and zero its value before HMAC.
		off = HeaderLen
		for _, a := range attrs {
			vLen := len(a.Value)
			if a.Type == AttrMessageAuthenticator {
				maStart := off + 2
				maEnd := maStart + vLen
				// zero out for HMAC computation
				for i := maStart; i < maEnd; i++ {
					out[i] = 0
				}
				h := hmac.New(md5.New, secret)
				h.Write(out)
				mac := h.Sum(nil)
				copy(out[maStart:maEnd], mac)
				break
			}
			off += 2 + vLen
		}
	}

	// Step 2: stamp Response Authenticator (RFC 2865 §3): MD5(Code+ID+Length+
	// RequestAuth+Attributes+Secret). Only for server-originated replies.
	switch p.Code {
	case CodeAccessAccept, CodeAccessReject, CodeAccessChallenge,
		CodeAccountingResponse:
		hh := md5.New()
		hh.Write(out[:4])
		hh.Write(reqAuth)
		hh.Write(out[HeaderLen:])
		hh.Write(secret)
		sum := hh.Sum(nil)
		copy(out[4:HeaderLen], sum)
	}

	return out, nil
}

// verifyMessageAuthenticator returns true iff ma == HMAC-MD5(secret) over packet
// with MA attribute zeroed.
func verifyMessageAuthenticator(packet, ma, secret []byte) bool {
	tmp := make([]byte, len(packet))
	copy(tmp, packet)
	// Find MA attribute and zero it.
	off := HeaderLen
	for off+2 <= len(tmp) {
		t := tmp[off]
		l := int(tmp[off+1])
		if l < 2 || off+l > len(tmp) {
			return false
		}
		if t == AttrMessageAuthenticator {
			for i := off + 2; i < off+l; i++ {
				tmp[i] = 0
			}
			break
		}
		off += l
	}
	h := hmac.New(md5.New, secret)
	h.Write(tmp)
	return hmac.Equal(h.Sum(nil), ma)
}

// DecodeUserPassword reverses the RFC 2865 §5.2 obfuscation:
//
//	b1 = MD5(secret + RequestAuthenticator)
//	c1 = p1 XOR b1
//	b2 = MD5(secret + c1)
//	c2 = p2 XOR b2
//	...
//
// Returns the cleartext password with trailing NULs stripped. Cap is the max
// number of 16-byte chunks the caller will accept (4 = 64 chars, matches
// RFC 2865 §5.2 mandatory minimum; we allow 8 = 128 for long passphrases).
func DecodeUserPassword(enc, reqAuth, secret []byte) (string, error) {
	if len(enc) == 0 || len(enc)%16 != 0 {
		return "", fmt.Errorf("radius: User-Password length %d not 16-byte aligned", len(enc))
	}
	if len(enc) > 128 {
		return "", fmt.Errorf("radius: User-Password length %d > 128 cap", len(enc))
	}
	out := make([]byte, len(enc))
	prev := reqAuth
	for i := 0; i < len(enc); i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(prev)
		mask := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = enc[i+j] ^ mask[j]
		}
		prev = enc[i : i+16]
	}
	// Strip trailing NULs.
	n := len(out)
	for n > 0 && out[n-1] == 0 {
		n--
	}
	return string(out[:n]), nil
}

// EncodeUserPassword is the inverse of DecodeUserPassword. We don't issue
// User-Password attributes in replies but tests need this for round-tripping
// and a Server-side change-of-authorization (CoA) extension would need it.
func EncodeUserPassword(plain string, reqAuth, secret []byte) []byte {
	pw := []byte(plain)
	// Pad to a 16-byte multiple (RFC 2865 §5.2 requires the encoded length be
	// a multiple of 16, minimum 16, capped at 128 by the spec).
	padLen := 16 - (len(pw) % 16)
	if padLen == 16 && len(pw) != 0 {
		// already aligned but we still need at least 16 bytes
		padLen = 0
	}
	if len(pw) == 0 {
		padLen = 16
	}
	pw = append(pw, make([]byte, padLen)...)
	if len(pw) > 128 {
		pw = pw[:128]
	}
	out := make([]byte, len(pw))
	prev := reqAuth
	for i := 0; i < len(pw); i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(prev)
		mask := h.Sum(nil)
		for j := 0; j < 16; j++ {
			out[i+j] = pw[i+j] ^ mask[j]
		}
		prev = out[i : i+16]
	}
	return out
}

// VerifyCHAP checks an RFC 2865 §2.2 CHAP-Password attribute. chap is the 17-
// byte CHAP-Password value (1 byte CHAP-ID + 16 byte MD5 response). challenge
// is the 16-byte CHAP-Challenge value (or the Request-Authenticator if the NAS
// omitted CHAP-Challenge per the spec).
func VerifyCHAP(password string, chap, challenge []byte) bool {
	if len(chap) != 17 || len(challenge) < 1 {
		return false
	}
	h := md5.New()
	h.Write(chap[:1])         // CHAP-ID
	h.Write([]byte(password)) // shared password
	h.Write(challenge)        // CHAP-Challenge (or Req-Auth fallback)
	return hmac.Equal(h.Sum(nil), chap[1:])
}

// VerifyAccountingRequest validates the Request Authenticator on an
// Accounting-Request: it must equal MD5(Code+ID+Length+0*16+Attrs+Secret).
// Returns true on match. RFC 2866 §3.
func VerifyAccountingRequest(packet, secret []byte) bool {
	if len(packet) < HeaderLen {
		return false
	}
	tmp := make([]byte, len(packet))
	copy(tmp, packet)
	for i := 4; i < HeaderLen; i++ {
		tmp[i] = 0
	}
	h := md5.New()
	h.Write(tmp)
	h.Write(secret)
	return hmac.Equal(h.Sum(nil), packet[4:HeaderLen])
}

// NewIdentifier returns a non-zero random byte for use as a Packet.Identifier
// when the server originates a request (currently unused — accept/reject re-use
// the request identifier). Exposed for completeness.
func NewIdentifier() uint8 {
	var b [1]byte
	_, _ = rand.Read(b[:])
	if b[0] == 0 {
		b[0] = 1
	}
	return b[0]
}
