// Package rdp builds Microsoft Remote Desktop launch artifacts for the
// CyberArk-style flow: users never type the privileged password — they run a
// short-lived helper script that injects credentials via cmdkey, then open the
// .rdp file.
package rdp

import (
	"fmt"
	"strings"
)

// LaunchParams are the connection details for one RDP session.
type LaunchParams struct {
	Host     string
	Port     int
	Username string
	Name     string // friendly filename / display name
}

// BuildRDPFile returns a Microsoft .rdp file body.
func BuildRDPFile(p LaunchParams) []byte {
	port := p.Port
	if port <= 0 {
		port = 3389
	}
	host := p.Host
	name := p.Name
	if name == "" {
		name = host
	}
	addr := fmt.Sprintf("%s:%d", host, port)

	lines := []string{
		"screen mode id:i:2",
		"use multimon:i:0",
		"session bpp:i:32",
		"compression:i:1",
		"keyboardhook:i:2",
		"displayconnectionbar:i:1",
		"full address:s:" + addr,
		"audiomode:i:0",
		"redirectprinters:i:0",
		"redirectcomports:i:0",
		"redirectsmartcards:i:1",
		"redirectclipboard:i:1",
		"autoreconnection enabled:i:1",
		"authentication level:i:2",
		"prompt for credentials:i:0",
		"negotiate security layer:i:1",
		"gatewayusagemethod:i:4",
		"gatewaycredentialssource:i:4",
	}
	if p.Username != "" {
		lines = append(lines, "username:s:"+p.Username)
	}
	_ = name // used by caller for Content-Disposition
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

// BuildLaunchScript returns a PowerShell script that stores credentials in
// Windows Credential Manager (cmdkey) and launches mstsc with the .rdp file.
// The password is embedded once; the script should be deleted after use.
func BuildLaunchScript(p LaunchParams, password, rdpFilename string) string {
	port := p.Port
	if port <= 0 {
		port = 3389
	}
	target := fmt.Sprintf("TERMSRV/%s", p.Host)
	if rdpFilename == "" {
		rdpFilename = p.Name + ".rdp"
	}
	// Escape single quotes for PowerShell single-quoted strings.
	esc := func(s string) string {
		return strings.ReplaceAll(s, "'", "''")
	}
	return fmt.Sprintf(`# PAM Platform — one-time RDP launcher
# Run this script on your Windows workstation, then delete it.
$ErrorActionPreference = 'Stop'
$target = '%s'
$user = '%s'
$pass = '%s'
$rdp = Join-Path $PSScriptRoot '%s'

Write-Host "Injecting short-lived credentials for $user @ %s ..."
cmdkey /generic:$target /user:$user /pass:$pass | Out-Null
if (-not (Test-Path $rdp)) { throw "RDP file not found: $rdp" }
Start-Process mstsc.exe -ArgumentList $rdp
Write-Host "Remote Desktop started. When finished, run: cmdkey /delete:$target"
`, esc(target), esc(p.Username), esc(password), esc(rdpFilename), esc(p.Host))
}
