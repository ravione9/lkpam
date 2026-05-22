package mfa

import (
	"strings"
	"testing"
)

func TestQRPNGDataURI(t *testing.T) {
	uri := OtpAuthURI("PAM Platform", "admin", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	data, err := QRPNGDataURI(uri, 200)
	if err != nil {
		t.Fatalf("QRPNGDataURI: %v", err)
	}
	if !strings.HasPrefix(data, "data:image/png;base64,") {
		t.Fatalf("unexpected prefix: %s", data[:min(32, len(data))])
	}
	if len(data) < 200 {
		t.Fatalf("QR data URI too short")
	}
}
