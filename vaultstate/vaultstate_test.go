package vaultstate

import (
	"context"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var (
	policy = `path "secret/nodes/bootable/*" { capabilities = ["read", "delete"]}`
)

func TestVaultStateManagerTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vaultConfig := RunVault(ctx)
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	vaultClient.SetToken(vaultTestRootToken)

	vaultClient.Sys().PutPolicy("testPolicy", policy)

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"testPolicy"}})
	if err != nil {
		t.Fatalf("Unable to create test token")
	}
	myToken := secret.Auth.ClientToken

	vaultClient.SetToken(myToken)

	vsm := NewVaultStateManager("nodes/bootable", vaultClient)

	testKeys := []string{"foo", "bar", "baz"}
	for _, key := range testKeys {
		if vsm.Active(key) {
			t.Errorf("Unactivated key returned as active: %s", key)
		}
	}

	vaultClient.SetToken(vaultTestRootToken)

	for _, key := range testKeys {
		err := vsm.Activate(key, time.Second)
		if err != nil {
			t.Errorf("Unable to activate %s: %v", key, err)
		}
	}

	vaultClient.SetToken(myToken)

	time.Sleep(500 * time.Millisecond)
	for _, key := range testKeys {
		if !vsm.Active(key) {
			t.Errorf("Activated key returned as inactive: %s", key)
		}
	}

	time.Sleep(600 * time.Millisecond)
	for _, key := range testKeys {
		if vsm.Active(key) {
			t.Errorf("Inactive key returned as active: %s", key)
		}
	}
}

func TestVaultStateManagerDeactivation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vaultConfig := RunVault(ctx)
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	vaultClient.SetToken(vaultTestRootToken)

	vaultClient.Sys().PutPolicy("testPolicy", policy)

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"testPolicy"}})
	if err != nil {
		t.Fatalf("Unable to create test token")
	}
	myToken := secret.Auth.ClientToken

	vaultClient.SetToken(myToken)

	vsm := NewVaultStateManager("nodes/bootable", vaultClient)

	testKeys := []string{"foo", "bar", "baz"}
	for _, key := range testKeys {
		if vsm.Active(key) {
			t.Errorf("Unactivated key returned as active: %s", key)
		}
	}

	vaultClient.SetToken(vaultTestRootToken)

	for _, key := range testKeys {
		err := vsm.Activate(key, time.Second)
		if err != nil {
			t.Errorf("Unable to activate %s: %v", key, err)
		}
	}

	vaultClient.SetToken(myToken)

	time.Sleep(500 * time.Millisecond)
	for _, key := range testKeys {
		if !vsm.Active(key) {
			t.Errorf("Activated key returned as inactive: %s", key)
		}
		err := vsm.Deactivate(key)
		if err != nil {
			t.Errorf("Unable to deactivate %s: %v", key, err)
		}
		if vsm.Active(key) {
			t.Errorf("Newly deactivated key returned as active: %s", key)
		}
	}
}
