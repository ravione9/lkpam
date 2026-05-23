package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"testing"
)

func TestUserPasswordRoundTrip(t *testing.T) {
	secret := []byte("STRONG-SECRET")
	reqAuth := bytes.Repeat([]byte{0xA5}, 16)
	cases := []string{
		"hunter2",
		"",
		"x",
		"sixteenbytespass", // exactly 16
		"longer-than-sixteen-bytes-password",
		"Sup3r$3cret-Pa55phrase!2026",
	}
	for _, want := range cases {
		enc := EncodeUserPassword(want, reqAuth, secret)
		if len(enc)%16 != 0 || len(enc) == 0 || len(enc) > 128 {
			t.Fatalf("enc length %d invalid for %q", len(enc), want)
		}
		got, err := DecodeUserPassword(enc, reqAuth, secret)
		if err != nil {
			t.Fatalf("decode %q: %v", want, err)
		}
		if got != want {
			t.Fatalf("round-trip: got %q want %q", got, want)
		}
	}
}

func TestUserPasswordBadInput(t *testing.T) {
	if _, err := DecodeUserPassword(nil, make([]byte, 16), []byte("k")); err == nil {
		t.Fatal("expected error on empty buffer")
	}
	if _, err := DecodeUserPassword(make([]byte, 17), make([]byte, 16), []byte("k")); err == nil {
		t.Fatal("expected error on unaligned length")
	}
	if _, err := DecodeUserPassword(make([]byte, 144), make([]byte, 16), []byte("k")); err == nil {
		t.Fatal("expected error on oversize length")
	}
}

func TestVerifyCHAP(t *testing.T) {
	secret := "letmein"
	challenge := bytes.Repeat([]byte{0x37}, 16)
	chapID := byte(0x42)

	h := md5.New()
	h.Write([]byte{chapID})
	h.Write([]byte(secret))
	h.Write(challenge)
	want := h.Sum(nil)

	chap := append([]byte{chapID}, want...)
	if !VerifyCHAP(secret, chap, challenge) {
		t.Fatal("VerifyCHAP returned false for valid response")
	}
	if VerifyCHAP("wrong", chap, challenge) {
		t.Fatal("VerifyCHAP accepted wrong password")
	}
	if VerifyCHAP(secret, chap[:16], challenge) {
		t.Fatal("VerifyCHAP accepted short response")
	}
}

func TestEncodeDecodeAccessRequestRoundTrip(t *testing.T) {
	secret := []byte("topsecret")

	pkt := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 0x77,
	}
	for i := range pkt.Authenticator {
		pkt.Authenticator[i] = byte(i + 1)
	}
	pkt.Attrs.AddString(AttrUserName, "alice")
	pkt.Attrs.Add(AttrUserPassword, EncodeUserPassword("hunter2", pkt.Authenticator[:], secret))
	pkt.Attrs.AddUint32(AttrNASPort, 7)
	pkt.Attrs.Add(AttrNASIPAddress, []byte{10, 1, 2, 3})

	wire, err := Encode(pkt, secret, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(wire, secret)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Code != CodeAccessRequest || got.Identifier != 0x77 {
		t.Fatalf("header mismatch")
	}
	if user := string(got.Attrs.Get(AttrUserName)); user != "alice" {
		t.Fatalf("user=%q", user)
	}
	pw, err := DecodeUserPassword(got.Attrs.Get(AttrUserPassword), got.Authenticator[:], secret)
	if err != nil {
		t.Fatalf("decode user-password: %v", err)
	}
	if pw != "hunter2" {
		t.Fatalf("pw=%q", pw)
	}
	if b := got.Attrs.Get(AttrNASPort); len(b) != 4 || binary.BigEndian.Uint32(b) != 7 {
		t.Fatalf("nas-port wrong")
	}
}

func TestMessageAuthenticatorVerify(t *testing.T) {
	secret := []byte("topsecret")
	pkt := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 5,
	}
	for i := range pkt.Authenticator {
		pkt.Authenticator[i] = byte(i)
	}
	pkt.Attrs.AddString(AttrUserName, "bob")
	// caller pre-stamps the MA placeholder so Encode does NOT re-sign it
	// (Encode only signs accept/reject/challenge replies)
	// Instead we build by hand:
	wire, _ := Encode(pkt, secret, nil)

	// Without MA in the request, Decode should accept.
	if _, err := Decode(wire, secret); err != nil {
		t.Fatalf("decode no-MA: %v", err)
	}

	// Add a bad MA attribute and confirm Decode rejects.
	bad := append([]byte(nil), wire...)
	// re-serialize with a bogus MA appended
	maAttr := append([]byte{AttrMessageAuthenticator, 18}, bytes.Repeat([]byte{0xFF}, 16)...)
	bad = append(bad, maAttr...)
	binary.BigEndian.PutUint16(bad[2:4], uint16(len(bad)))
	if _, err := Decode(bad, secret); err == nil {
		t.Fatal("Decode should reject tampered Message-Authenticator")
	}
}

func TestResponseAuthenticatorSetOnAccept(t *testing.T) {
	secret := []byte("topsecret")
	req := &Packet{Code: CodeAccessRequest, Identifier: 9}
	for i := range req.Authenticator {
		req.Authenticator[i] = byte(0xA0 + i)
	}
	req.Attrs.AddString(AttrUserName, "carol")

	reply := &Packet{Code: CodeAccessAccept, Identifier: 9}
	reply.Attrs.AddUint32(AttrServiceType, ServiceAdministrative)
	reply.Attrs.AddString(AttrReplyMessage, "ok")

	wire, err := Encode(reply, secret, req.Authenticator[:])
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Recompute the response authenticator and compare.
	h := md5.New()
	h.Write(wire[:4])
	h.Write(req.Authenticator[:])
	h.Write(wire[HeaderLen:])
	h.Write(secret)
	want := h.Sum(nil)
	if !bytes.Equal(wire[4:HeaderLen], want) {
		t.Fatal("Response Authenticator was not stamped correctly")
	}
}
