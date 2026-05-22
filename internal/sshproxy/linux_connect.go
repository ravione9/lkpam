package sshproxy

import (
	"fmt"
	"log"

	"github.com/example/pam-platform/internal/linuxprovision"
	"github.com/example/pam-platform/internal/policy"
	"golang.org/x/crypto/ssh"
)

// dialLinux connects to a Linux target as the portal user. Passthrough is tried first.
// The privileged bootstrap account is used only to provision the per-user account.
func (s *Server) dialLinux(
	targetAddr string,
	targetKind, portalUser, ptPassword, privUser, privPassword, linuxPriv string,
	authMethods []ssh.AuthMethod,
) (client *ssh.Client, deviceUser, authMode string, err error) {
	linuxUser := linuxprovision.LinuxUsername(portalUser)

	if ptPassword != "" {
		cfg := s.buildDownstreamConfig(linuxUser, ptPassword, authMethods)
		log.Printf("ssh-proxy: linux passthrough %s as %q", targetAddr, linuxUser)
		c, err := ssh.Dial("tcp", targetAddr, cfg)
		if err == nil {
			return c, linuxUser, "passthrough", nil
		}
		if privUser == "" || privPassword == "" || !isDownstreamAuthFailure(err) {
			return nil, linuxUser, "passthrough", err
		}
		log.Printf("ssh-proxy: linux passthrough failed for %q — provisioning via %q", linuxUser, privUser)
	}

	if privUser == "" || privPassword == "" {
		return nil, linuxUser, "passthrough", fmt.Errorf(
			"no bootstrap account for provisioning — link a privileged account (e.g. pam-svc) to this target")
	}

	bootstrap, err := ssh.Dial("tcp", targetAddr, s.buildDownstreamConfig(privUser, privPassword, authMethods))
	if err != nil {
		return nil, linuxUser, "provision", fmt.Errorf("bootstrap login as %q: %w", privUser, err)
	}
	defer bootstrap.Close()

	if ptPassword == "" {
		return nil, linuxUser, "provision", fmt.Errorf("portal password required to provision Linux user %q", linuxUser)
	}
	if err := linuxprovision.EnsureUser(bootstrap, portalUser, ptPassword, linuxPriv); err != nil {
		return nil, linuxUser, "provision", err
	}

	cfg := s.buildDownstreamConfig(linuxUser, ptPassword, authMethods)
	c, err := ssh.Dial("tcp", targetAddr, cfg)
	if err != nil {
		return nil, linuxUser, "provisioned", fmt.Errorf("login as provisioned user %q: %w", linuxUser, err)
	}
	return c, linuxUser, "provisioned", nil
}

func useLinuxPerUserLogin(kind string) bool {
	return policy.IsLinuxKind(kind)
}
