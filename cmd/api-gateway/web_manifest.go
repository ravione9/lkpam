package main

import (
	"bytes"
	"encoding/json"
	"strings"
)

var minimalWebManifest = []byte(`{}`)

// webPathOnly strips an embedded ?query from a proxied asset path.
func webPathOnly(path string) string {
	if q := strings.IndexByte(path, '?'); q >= 0 {
		return path[:q]
	}
	return path
}

func isWebManifestPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(webPathOnly(path)), ".webmanifest")
}

// coerceWebManifestBody returns valid manifest JSON. Appliances sometimes serve
// HTML login pages, error text, or JSON with trailing bytes for site.webmanifest;
// browsers reject those with "Unexpected data after root element".
func coerceWebManifestBody(body []byte, status int) []byte {
	if status >= 400 || len(body) == 0 {
		return minimalWebManifest
	}
	body = bytes.TrimSpace(body)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	if len(body) == 0 {
		return minimalWebManifest
	}
	if json.Valid(body) {
		return body
	}
	if trimmed := extractFirstJSONObject(body); trimmed != nil {
		return trimmed
	}
	if looksLikeHTML(body) {
		return minimalWebManifest
	}
	return minimalWebManifest
}

func looksLikeHTML(body []byte) bool {
	probe := bytes.TrimSpace(bytes.ToLower(body))
	if len(probe) > 128 {
		probe = probe[:128]
	}
	return bytes.HasPrefix(probe, []byte("<!doctype")) ||
		bytes.HasPrefix(probe, []byte("<html")) ||
		bytes.HasPrefix(probe, []byte("<head"))
}

func extractFirstJSONObject(body []byte) []byte {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil
	}
	if !json.Valid(raw) {
		return nil
	}
	return raw
}
