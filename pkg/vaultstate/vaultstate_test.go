package vaultstate

import (
	"context"
	"testing"
	"time"

	vaulttest "github.com/PolarGeospatialCenter/dockertest/pkg/vault"
	vault "github.com/hashicorp/vault/api"
)

var (
	policy = `path "secret/data/nodes/bootable/*" { capabilities = ["read", "delete"]}`
)

func TestVaultStateManagerTimeout(t *testing.T) {
	ctx := context.Background()
	vaultInstance, err := vaulttest.Run(ctx)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	defer vaultInstance.Stop(ctx)

	vaultClient, err := vault.NewClient(vaultInstance.Config())
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	vaultTestRootToken := vaultInstance.RootToken()
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
	ctx := context.Background()
	vaultInstance, err := vaulttest.Run(ctx)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	defer vaultInstance.Stop(ctx)

	vaultClient, err := vault.NewClient(vaultInstance.Config())
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	vaultTestRootToken := vaultInstance.RootToken()
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

func TestVaultStateManagerStatus(t *testing.T) {
	ctx := context.Background()
	vaultInstance, err := vaulttest.Run(ctx)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	defer vaultInstance.Stop(ctx)

	vaultClient, err := vault.NewClient(vaultInstance.Config())
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	vaultTestRootToken := vaultInstance.RootToken()
	vaultClient.SetToken(vaultTestRootToken)
	vsm := NewVaultStateManager("nodes/bootable", vaultClient)
	if vsm.Status("unsetkey") != "record for unsetkey not found" {
		t.Errorf("Incorrect status returned for unset key: actual '%s', expected 'record for unsetkey not found'", vsm.Status("unsetkey"))
	}

	err = vsm.Activate("testkey", time.Second)
	if err != nil {
		t.Errorf("Error activating testkey: %s", err)
	}
	expected := "testkey: TTL 1s, Created at "
	actual := string(vsm.Status("testkey")[:len(expected)])
	if actual != expected {
		t.Errorf("Incorrect status returned for test key: actually starts with '%s', expected to start with '%s'", actual, expected)
	}
}
