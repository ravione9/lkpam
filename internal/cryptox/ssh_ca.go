package cryptox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// NewSSHCA creates a new Ed25519 keypair suitable for use as an SSH
// certificate authority. The returned PEM-encoded private key should be stored
// (encrypted) in the vault and never leave it.
func NewSSHCA() (privPEM []byte, pubAuth []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-ca: gen key: %w", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "pam-ssh-ca")
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-ca: marshal priv: %w", err)
	}
	privPEM = pem.EncodeToMemory(pemBlock)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh-ca: new pub: %w", err)
	}
	pubAuth = ssh.MarshalAuthorizedKey(sshPub)
	return privPEM, pubAuth, nil
}

// IssueUserCert signs userPubKey as an SSH user certificate. The certificate
// has the given principals (e.g. "netadmin") and a TTL.
func IssueUserCert(caPrivPEM []byte, userPubKey ssh.PublicKey, principals []string, ttl time.Duration) (*ssh.Certificate, error) {
	signer, err := ssh.ParsePrivateKey(caPrivPEM)
	if err != nil {
		return nil, fmt.Errorf("ssh-ca: parse priv: %w", err)
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             userPubKey,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("pam-%d", now.Unix()),
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("ssh-ca: sign: %w", err)
	}
	return cert, nil
}
