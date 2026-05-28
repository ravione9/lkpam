package main

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestDecompressUpstreamBodyGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("<html>ok</html>"))
	_ = zw.Close()
	out, err := decompressUpstreamBody(buf.Bytes(), "gzip")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "<html>ok</html>" {
		t.Fatalf("got %q", out)
	}
}

func TestDecompressUpstreamBodyPlain(t *testing.T) {
	out, err := decompressUpstreamBody([]byte("plain"), "")
	if err != nil || string(out) != "plain" {
		t.Fatalf("plain passthrough failed: %q err=%v", out, err)
	}
}
