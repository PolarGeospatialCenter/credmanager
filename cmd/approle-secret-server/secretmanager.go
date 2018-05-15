package main

import (
	"fmt"

	vault "github.com/hashicorp/vault/api"
)

type IDable interface {
	ID() string
}

type AppRoleSecretManager struct {
	vaultClient *vault.Client
}

func NewAppRoleSecretManager(c *vault.Client) *AppRoleSecretManager {
	return &AppRoleSecretManager{vaultClient: c}
}

func (m *AppRoleSecretManager) getRoleName(id string) string {
	return fmt.Sprintf("credmanager-%s", id)
}

func (m *AppRoleSecretManager) GetSecret(id string) (string, error) {
	roleName := m.getRoleName(id)
	secret, err := m.vaultClient.Logical().Write(fmt.Sprintf("auth/approle/role/%s/secret-id", roleName), nil)
	if err != nil {
		return "", err
	}
	rawSecretIDsecret, ok := secret.Data["secret_id"]
	if !ok {
		return "", fmt.Errorf("vault failed to return a secret_id")
	}
	return rawSecretIDsecret.(string), nil
}
