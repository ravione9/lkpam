package rdpproxy

import "testing"

func TestResolveRDPReachableHost(t *testing.T) {
	t.Setenv("PAM_RDP_DOCKER_HOST", "my-host")
	if got := resolveRDPReachableHost("localhost"); got != "my-host" {
		t.Fatalf("localhost = %q, want my-host", got)
	}
	t.Setenv("PAM_RDP_DOCKER_HOST", "")
	if got := resolveRDPReachableHost("127.0.0.1"); got != "host.docker.internal" {
		t.Fatalf("127.0.0.1 = %q, want host.docker.internal", got)
	}
	if got := resolveRDPReachableHost("10.0.0.5"); got != "10.0.0.5" {
		t.Fatalf("10.0.0.5 = %q", got)
	}
}

func TestNormalizeRDPPort(t *testing.T) {
	if normalizeRDPPort(0) != 3389 {
		t.Fatal("zero port")
	}
	if normalizeRDPPort(3390) != 3390 {
		t.Fatal("explicit port")
	}
}
