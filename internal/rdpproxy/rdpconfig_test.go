package rdpproxy

import "testing"

func TestRdpGuacParamsRecordingDisablesCaching(t *testing.T) {
	p := rdpGuacParams("192.168.1.10", 3389, "Administrator", "secret", "/rec/s", "rdp-1", true)
	for _, key := range []string{
		"disable-bitmap-caching",
		"disable-offscreen-caching",
		"disable-glyph-caching",
		"disable-gfx",
		"recording-include-keys",
	} {
		if p[key] != "true" {
			t.Fatalf("expected %s=true when recording, got %q", key, p[key])
		}
	}
	if p["recording-path"] != "/rec/s" {
		t.Fatalf("recording-path: got %q", p["recording-path"])
	}
}

func TestRdpGuacParamsNoRecordingSkipsRecordingKeys(t *testing.T) {
	p := rdpGuacParams("host", 3389, "u", "p", "/rec/s", "rdp-1", false)
	if _, ok := p["recording-path"]; ok {
		t.Fatal("recording-path should not be set when record=false")
	}
	if p["disable-bitmap-caching"] != "true" {
		t.Fatal("caching should stay disabled for live session fidelity too")
	}
}
