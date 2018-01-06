package main

import (
	"context"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
)

func TestCreateNodeToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vaultConfig := RunVault(ctx)
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	err = loadVaultPolicyData(vaultClient)
	if err != nil {
		t.Fatalf("Unable to setup vault policies: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"issuer"}})
	if err != nil {
		t.Fatalf("Unable to create issuer token: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	tokenManager := NewTokenManager(vaultClient)

	store, _ := inventory.NewSampleInventoryStore()
	nodes, _ := store.Nodes()
	node := nodes["sample0001"]

	token, err := tokenManager.CreateNodeToken(node, []string{"bar-worker-ssh-cert"})
	if err != nil {
		t.Errorf("Unable to create token: %v", err)
	}
	t.Logf("Token: %s", token)

}

func TestLookupTokenRole(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vaultConfig := RunVault(ctx)
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	err = loadVaultPolicyData(vaultClient)
	if err != nil {
		t.Fatalf("Unable to setup vault policies: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"issuer"}})
	if err != nil {
		t.Fatalf("Unable to create issuer token: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	tokenManager := NewTokenManager(vaultClient)

	roleData, err := tokenManager.lookupTokenRole("credmanager-bar-worker")
	if err != nil {
		t.Fatalf("Unable to lookup role: %v", err)
	}

	if name, ok := roleData["name"].(string); !ok || name != "credmanager-bar-worker" {
		t.Errorf("Invalid object returned from role lookup or name didn't match")
	}
}
