package main

import (
	"fmt"

	vault "github.com/hashicorp/vault/api"
	inventorytypes "github.umn.edu/pgc-devops/inventory-ingest/inventory/types"
)

type TokenManager struct {
	vault *vault.Client
}

func NewTokenManager(vault *vault.Client) *TokenManager {
	m := &TokenManager{}
	m.vault = vault
	m.vault.SetWrappingLookupFunc(func(op, path string) string {
		if op == "POST" && path == "auth/token/create-orphan" {
			return "5m"
		} else {
			return ""
		}
	})
	return m
}

func (m *TokenManager) createNodePolicy(node *inventorytypes.InventoryNode) error {
	return fmt.Errorf("Not implemented")
}

func (m *TokenManager) nodePolicyNames(node *inventorytypes.InventoryNode) []string {
	return []string{}
}

func (m *TokenManager) CreateNodeToken(node *inventorytypes.InventoryNode) (string, error) {
	tokenRequest := vault.TokenCreateRequest{Policies: m.nodePolicyNames(node)}
	secret, err := m.vault.Auth().Token().CreateOrphan(&tokenRequest)
	if err != nil {
		return "", err
	}
	return secret.WrapInfo.Token, nil
}
