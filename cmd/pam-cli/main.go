// pam-cli is a thin CLI client. It logs in, lists targets, and triggers
// access requests. The actual SSH connection should be made directly to the
// SSH proxy on port 2222 once you have an approval.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

func main() {
	gw := flag.String("gw", "http://localhost:8080", "API gateway URL")
	flag.Parse()
	if flag.NArg() < 1 {
		usage()
		return
	}
	cmd := flag.Arg(0)
	switch cmd {
	case "login":
		login(*gw)
	case "request":
		if flag.NArg() < 3 {
			fmt.Println("usage: pam-cli request <target-id> <reason>")
			os.Exit(1)
		}
		request(*gw, flag.Arg(1), flag.Arg(2))
	case "ca":
		ca(*gw)
	default:
		usage()
	}
}

func usage() {
	fmt.Println(`pam-cli  — reference client for the PAM platform
usage:
  pam-cli login                       Sign in and print a JWT
  pam-cli ca                          Fetch the SSH CA public key
  pam-cli request <target-id> <why>   File a JIT access request`)
}

func login(gw string) {
	var u, p string
	fmt.Print("username: ")
	fmt.Scanln(&u)
	fmt.Print("password: ")
	fmt.Scanln(&p)
	body, _ := json.Marshal(map[string]string{"Username": u, "Password": p})
	resp, err := http.Post(gw+"/api/auth/login", "application/json", bytes.NewReader(body))
	must(err)
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}

func ca(gw string) {
	resp, err := http.Get(gw + "/api/vault/ca/pub")
	must(err)
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
}

func request(gw, target, reason string) {
	body, _ := json.Marshal(map[string]any{
		"user_id":     1, // real impl: derive from JWT
		"target_id":   atoi(target),
		"reason":      reason,
		"ttl_seconds": 1800,
	})
	resp, err := http.Post(gw+"/api/approval/requests", "application/json", bytes.NewReader(body))
	must(err)
	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
	fmt.Println()
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func atoi(s string) int64 {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int64(r-'0')
	}
	return n
}
