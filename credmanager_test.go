package main

import (
	"context"
	"testing"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.umn.edu/pgc-devops/credmanager-api/types"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
)

func getTestCredmanagerHandler(ctx context.Context) *CredmanagerHandler {
	consulConfig := RunConsul(ctx)
	vaultConfig := RunVault(ctx)
	client, _ := consul.NewClient(consulConfig)
	store, _ := inventory.NewSampleInventoryStore()
	vault, _ := vault.NewClient(vaultConfig)
	return &CredmanagerHandler{Store: store, Consul: client, Vault: vault}
}

func TestValidNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := getTestCredmanagerHandler(ctx)

	if !h.requestFromValidNode(&types.TokenRequest{Hostname: "bar-ab01-02"}) {
		t.Fatalf("Request from valid node rejected.")
	}
}
