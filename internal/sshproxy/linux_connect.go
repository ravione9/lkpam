package sshproxy

import (
	"fmt"
	"log"

	"github.com/example/pam-platform/internal/linuxprovision"
	"github.com/example/pam-platform/internal/policy"
	"golang.org/x/crypto/ssh"
)

// dialLinux connects to a Linux target as the portal user. Passthrough is tried first.
// The privileged bootstrap account is used to provision/sync the per-user account.
func (s *Server) dialLinux(
	targetAddr string,
	targetKind, portalUser, ptPassword, privUser, privPassword, linuxPriv string,
	authMethods []ssh.AuthMethod,
) (client *ssh.Client, deviceUser, authMode string, err error) {
	linuxUser := linuxprovision.LinuxUsername(portalUser)

	if ptPassword == "" {
		return nil, linuxUser, "passthrough", fmt.Errorf("portal password required for Linux login")
	}

	// Always sync when a bootstrap account exists — this covers both granting (sudo/root)
	// AND revoking (none) sudoers access. Without a bootstrap account we cannot provision.
	if privUser != "" && privPassword != "" {
		if err := s.syncLinuxAccount(targetAddr, portalUser, ptPassword, privUser, privPassword, linuxPriv, authMethods); err != nil {
			log.Printf("ssh-proxy: linux privilege sync for %q: %v", linuxUser, err)
			if linuxPriv == "sudo" || linuxPriv == "root" {
				return nil, linuxUser, "provision", fmt.Errorf(
					"could not apply Linux sudo policy for %q (check pam-svc bootstrap account): %w", linuxUser, err)
			}
			// Policy requires no elevation — block if we could not remove stale sudoers.
			return nil, linuxUser, "provision", fmt.Errorf(
				"could not revoke Linux sudo for %q (check pam-svc bootstrap account): %w", linuxUser, err)
		}
	} else if (linuxPriv == "sudo" || linuxPriv == "root") {
		// Sudo was granted in PAM but there is no bootstrap (privileged) account
		// configured for this target — the SSH proxy cannot write the sudoers entry.
		// Allow the connection but print a clear banner so both the user and admin
		// know what to fix: Safes → add a pam-svc account for this target.
		log.Printf("ssh-proxy: sudo granted for %q on %s but no bootstrap account configured — sudoers cannot be provisioned",
			linuxUser, targetAddr)
		// We still allow the connection; the banner is shown below.
	}

	cfg := s.buildDownstreamConfig(linuxUser, ptPassword, authMethods)
	log.Printf("ssh-proxy: linux passthrough %s as %q (linux_priv=%s)", targetAddr, linuxUser, linuxPriv)
	c, err := ssh.Dial("tcp", targetAddr, cfg)
	if err == nil {
		return c, linuxUser, "passthrough", nil
	}
	if privUser == "" || privPassword == "" || !isDownstreamAuthFailure(err) {
		return nil, linuxUser, "passthrough", err
	}
	log.Printf("ssh-proxy: linux passthrough failed for %q — provisioning via %q", linuxUser, privUser)

	bootstrap, err := ssh.Dial("tcp", targetAddr, s.buildDownstreamConfig(privUser, privPassword, authMethods))
	if err != nil {
		return nil, linuxUser, "provision", fmt.Errorf("bootstrap login as %q: %w", privUser, err)
	}
	defer bootstrap.Close()

	if err := linuxprovision.EnsureUser(bootstrap, portalUser, ptPassword, linuxPriv); err != nil {
		return nil, linuxUser, "provision", err
	}

	c, err = ssh.Dial("tcp", targetAddr, cfg)
	if err != nil {
		return nil, linuxUser, "provisioned", fmt.Errorf("login as provisioned user %q: %w", linuxUser, err)
	}
	return c, linuxUser, "provisioned", nil
}

// syncLinuxAccount updates password and /etc/sudoers.d via the bootstrap account.
func (s *Server) syncLinuxAccount(targetAddr, portalUser, ptPassword, privUser, privPassword, linuxPriv string, authMethods []ssh.AuthMethod) error {
	if privUser == "" || privPassword == "" {
		return fmt.Errorf("no bootstrap account linked to target")
	}
	bootstrap, err := ssh.Dial("tcp", targetAddr, s.buildDownstreamConfig(privUser, privPassword, authMethods))
	if err != nil {
		return fmt.Errorf("bootstrap login: %w", err)
	}
	defer bootstrap.Close()
	if err := linuxprovision.EnsureUser(bootstrap, portalUser, ptPassword, linuxPriv); err != nil {
		return err
	}
	log.Printf("ssh-proxy: synced Linux account %q (privilege=%s)", linuxprovision.LinuxUsername(portalUser), linuxPriv)
	return nil
}

func useLinuxPerUserLogin(kind string) bool {
	return policy.IsLinuxKind(kind)
}
