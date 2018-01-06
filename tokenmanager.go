package main

import (
	"bytes"
	"fmt"
	"html/template"

	vault "github.com/hashicorp/vault/api"
	inventorytypes "github.umn.edu/pgc-devops/inventory-ingest/inventory/types"
)

type TokenManager struct {
	vault          *vault.Client
	roleName       string
	policyTemplate string
}

func NewTokenManager(vault *vault.Client, policyTemplate string, roleName string) *TokenManager {
	m := &TokenManager{}
	m.vault = vault
	m.policyTemplate = policyTemplate
	m.roleName = roleName
	createEndpoint := fmt.Sprintf("auth/token/create/%s", m.roleName)
	m.vault.SetWrappingLookupFunc(func(op, path string) string {
		if op == "POST" && path == createEndpoint {
			return "5m"
		} else {
			return ""
		}
	})
	return m
}

func (m *TokenManager) renderNodePolicy(node *inventorytypes.InventoryNode) (string, error) {
	tmpl, err := template.New("policyTemplate").Parse(m.policyTemplate)
	if err != nil {
		return "", err
	}
	data := &struct{ Node *inventorytypes.InventoryNode }{Node: node}
	var policy bytes.Buffer
	err = tmpl.Execute(&policy, data)
	return policy.String(), err
}

func (m *TokenManager) createNodePolicy(node *inventorytypes.InventoryNode) error {
	policy, err := m.renderNodePolicy(node)
	if err != nil {
		return err
	}
	return m.vault.Sys().PutPolicy(m.nodePolicyName(node), policy)
}

func (m *TokenManager) nodePolicyName(node *inventorytypes.InventoryNode) string {
	return fmt.Sprintf("credmanager-%s", node.ID())
}

func (m *TokenManager) CreateNodeToken(node *inventorytypes.InventoryNode) (string, error) {
	err := m.createNodePolicy(node)
	if err != nil {
		return "", err
	}

	tokenRequest := vault.TokenCreateRequest{Policies: []string{m.nodePolicyName(node)}}
	secret, err := m.vault.Auth().Token().CreateWithRole(&tokenRequest, m.roleName)
	if err != nil {
		return "", err
	}
	if secret.WrapInfo == nil {
		return "", fmt.Errorf("no wrapped token issued, probably a bug related to the wrapped token creation endpoint")
	}
	return secret.WrapInfo.Token, nil
}
