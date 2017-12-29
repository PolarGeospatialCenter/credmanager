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

	cfg := readConfig()
	policyTemplate := cfg.GetString("vault.policy.template")
	tokenManager := NewTokenManager(vaultClient, policyTemplate)

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
