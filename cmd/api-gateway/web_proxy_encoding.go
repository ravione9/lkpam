package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// decompressUpstreamBody returns plaintext when FortiGate (or similar) sends gzip.
// The upstream client uses DisableCompression so we always receive raw bytes.
func decompressUpstreamBody(body []byte, contentEncoding string) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "" || enc == "identity" {
		return body, nil
	}
	if strings.Contains(enc, "gzip") {
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("gzip decode: %w", err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("gzip read: %w", err)
		}
		return out, nil
	}
	return body, nil
}

// stripResponseEncoding removes encoding headers before sending a rewritten
// (uncompressed) body to the browser — prevents ERR_CONTENT_DECODING_FAILED.
func stripResponseEncoding(h http.Header) {
	h.Del("Content-Encoding")
	h.Del("Transfer-Encoding")
}
