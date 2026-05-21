package rdp

import (
	"context"

	"github.com/example/pam-platform/internal/vault"
)

// VaultAdapter wraps vault.Vault for ephemeral RDP session secrets.
type VaultAdapter struct{ V *vault.Vault }

func (a *VaultAdapter) PutSessionSecret(name string, plaintext []byte) error {
	return a.V.PutSecret(context.Background(), name, plaintext, nil)
}

func (a *VaultAdapter) GetSessionSecret(name string) ([]byte, error) {
	return a.V.GetSecret(context.Background(), name)
}

func (a *VaultAdapter) DeleteSessionSecret(name string) error {
	return a.V.DeleteSecret(context.Background(), name)
}
