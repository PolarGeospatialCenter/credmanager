package vaultstate

import (
	"context"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

func TestVaultStateManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vaultConfig := RunVault(ctx)
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	vaultClient.SetToken(vaultTestRootToken)

	vsm := NewVaultStateManager("nodes/bootable", vaultClient)

	testKeys := []string{"foo", "bar", "baz"}
	for _, key := range testKeys {
		if vsm.Active(key) {
			t.Errorf("Unactivated key returned as active: %s", key)
		}
	}

	for _, key := range testKeys {
		vsm.Activate(key, time.Second)
	}

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
