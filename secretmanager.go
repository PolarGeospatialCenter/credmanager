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

func (m *AppRoleSecretManager) getRoleName(obj IDable) string {
	return fmt.Sprintf("credmanager-%s", obj.ID())
}

func (m *AppRoleSecretManager) GetSecret(obj IDable) (string, error) {
	roleName := m.getRoleName(obj)
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
