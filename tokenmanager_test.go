package main

import (
	"context"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
)

func TestCreateNodePolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vaultConfig := RunVault(ctx)
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	vaultClient.SetToken(vaultTestRootToken)

	err = createVaultTokenRole(vaultClient, "credmanager", issuerRole)
	if err != nil {
		t.Fatalf("Unable to create credmanager role: %v", err)
	}

	err = vaultClient.Sys().PutPolicy("issuer", issuerPolicy)
	if err != nil {
		t.Fatalf("Unable to create issuer policy: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"issuer"}})
	if err != nil {
		t.Fatalf("Unable to create issuer token: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	cfg := readConfig()
	policyTemplate := cfg.GetString("vault.policy.template")
	tokenManager := NewTokenManager(vaultClient, policyTemplate, "credmanager")

	store, _ := inventory.NewSampleInventoryStore()
	nodes, _ := store.Nodes()
	node := nodes["sample0001"]
	err = tokenManager.createNodePolicy(node)
	if err != nil {
		t.Fatalf("Unable to create node policy: %v", err)
	}

	policy, err := vaultClient.Sys().GetPolicy(tokenManager.nodePolicyName(node))
	if err != nil {
		t.Fatalf("Policy not found after creation: %v", err)
	}

	policyString, err := tokenManager.renderNodePolicy(node)
	if err != nil {
		t.Fatalf("Unable to render node policy template: %v", err)
	}

	if len(policy) == 0 || policy != policyString {
		t.Fatalf("Retrieved policy doesn't match template: %v", err)
	}

}

func TestCreateNodeToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vaultConfig := RunVault(ctx)
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	err = createVaultTokenRole(vaultClient, "credmanager", issuerRole)
	if err != nil {
		t.Fatalf("Unable to create credmanager role: %v", err)
	}

	err = vaultClient.Sys().PutPolicy("issuer", issuerPolicy)
	if err != nil {
		t.Fatalf("Unable to create issuer policy: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"issuer"}})
	if err != nil {
		t.Fatalf("Unable to create issuer token: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	cfg := readConfig()
	policyTemplate := cfg.GetString("vault.policy.template")
	tokenManager := NewTokenManager(vaultClient, policyTemplate, "credmanager")

	store, _ := inventory.NewSampleInventoryStore()
	nodes, _ := store.Nodes()
	node := nodes["sample0001"]

	token, err := tokenManager.CreateNodeToken(node)
	if err != nil {
		t.Errorf("Unable to create token: %v", err)
	}
	t.Logf("Token: %s", token)

}
