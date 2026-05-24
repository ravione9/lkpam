package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestIsWebManifestPath(t *testing.T) {
	if !isWebManifestPath("/site.webmanifest") {
		t.Fatal("expected manifest path")
	}
	if !isWebManifestPath("/favicon/site.webmanifest?v=2") {
		t.Fatal("expected manifest path with query")
	}
	if isWebManifestPath("/site.webmanifest.bak") {
		t.Fatal("suffix must match extension")
	}
}

func TestCoerceWebManifestBody(t *testing.T) {
	valid := []byte(`{"name":"fg","icons":[]}`)
	if got := coerceWebManifestBody(valid, 200); !bytes.Equal(got, valid) {
		t.Fatalf("valid json changed: %s", got)
	}
	if got := coerceWebManifestBody([]byte(`<!DOCTYPE html><html></html>`), 200); !bytes.Equal(got, minimalWebManifest) {
		t.Fatalf("html should become minimal: %s", got)
	}
	if got := coerceWebManifestBody(nil, 404); !bytes.Equal(got, minimalWebManifest) {
		t.Fatal("404 should become minimal")
	}
	corrupt := append(valid, []byte("\n<script>bad</script>")...)
	got := coerceWebManifestBody(corrupt, 200)
	if !json.Valid(got) {
		t.Fatalf("expected valid json after trim, got %s", got)
	}
	if !bytes.Equal(got, valid) {
		t.Fatalf("trimmed body mismatch: %s", got)
	}
}

func TestMimeForWebPathQuery(t *testing.T) {
	if mimeForWebPath("/site.webmanifest?v=1") != "application/manifest+json; charset=utf-8" {
		t.Fatal("manifest mime with query")
	}
}
