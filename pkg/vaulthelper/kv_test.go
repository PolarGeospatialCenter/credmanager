package vaulthelper

import (
	"context"
	"testing"

	vaulttest "github.com/PolarGeospatialCenter/dockertest/pkg/vault"
	"github.com/go-test/deep"
	vault "github.com/hashicorp/vault/api"
)

func TestKVDataPathV1(t *testing.T) {
	kv := &KV{MountPoint: "kv1", version: 1, Client: nil}
	dataPath := kv.dataPath("foo")
	if dataPath != "kv1/foo" {
		t.Errorf("Wrong data path returned for v1 mount, expected 'kv1/foo', got '%s'", dataPath)
	}
}

func TestKVDataPathVDefault(t *testing.T) {
	kv := &KV{MountPoint: "secret", Client: nil}
	dataPath := kv.dataPath("foo")
	if dataPath != "secret/data/foo" {
		t.Errorf("Wrong data path returned for v1 mount, expected 'secret/data/foo', got '%s'", dataPath)
	}
}

func TestKVDataPathV2(t *testing.T) {
	kv := &KV{MountPoint: "kv2", version: 2, Client: nil}
	dataPath := kv.dataPath("foo")
	if dataPath != "kv2/data/foo" {
		t.Errorf("Wrong data path returned for v1 mount, expected 'kv2/data/foo', got '%s'", dataPath)
	}
}

func mountV1KVBackend(vaultClient *vault.Client, mountPath string) error {
	mount := &vault.MountInput{
		Type:        "kv",
		Description: "Version 1 KV Store",
		Config: vault.MountConfigInput{
			DefaultLeaseTTL: "86400",
			MaxLeaseTTL:     "86400",
			ForceNoCache:    true,
			PluginName:      "kv",
		},
		Local:      true,
		PluginName: "kv",
		Options:    map[string]string{"version": "1"},
	}
	err := vaultClient.Sys().Mount(mountPath, mount)
	return err
}

func TestGetMountVersionKV1(t *testing.T) {
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

	v1mountPath := "kv1"

	err = mountV1KVBackend(vaultClient, v1mountPath)
	if err != nil {
		t.Fatalf("Unable to mount v1 of kv backend: %v", err)
	}

	version, err := GetMountVersion(vaultClient, v1mountPath)
	if err != nil {
		t.Errorf("unable to determine mount version: %v", err)
	}

	if version != 1 {
		t.Errorf("expected version 1, got %d", version)
	}
}

func TestGetMountVersionKVDefault(t *testing.T) {
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

	version, err := GetMountVersion(vaultClient, "secret")
	if err != nil {
		t.Errorf("unable to determine mount version: %v", err)
	}

	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}
}

func TestReadWriteV1(t *testing.T) {
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

	v1mountPath := "kv1"

	err = mountV1KVBackend(vaultClient, v1mountPath)
	if err != nil {
		t.Fatalf("Unable to mount v1 of kv backend: %v", err)
	}

	kv := NewKV(vaultClient, v1mountPath, 1)

	data := map[string]interface{}{"value": "bar", "ttl": "1s"}
	err = kv.Write("foo", data, nil)
	if err != nil {
		t.Errorf("failed to write: %v", err)
	}

	readData, _, err := kv.ReadLatest("foo")
	if err != nil {
		t.Errorf("failed to read: %v", err)
	}

	if diff := deep.Equal(readData, data); len(diff) > 0 {
		t.Errorf("Data read doesn't match what was written:")
		for _, l := range diff {
			t.Error(l)
		}
	}
}

func TestReadWriteVDefault(t *testing.T) {
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

	mountPath := "secret"

	kv := &KV{MountPoint: mountPath, Client: vaultClient}
	data := map[string]interface{}{"value": "bar", "ttl": "1s"}
	err = kv.Write("foo", data, nil)
	if err != nil {
		t.Errorf("failed to write: %v", err)
	}

	readData, _, err := kv.ReadLatest("foo")
	if err != nil {
		t.Errorf("failed to read: %v", err)
	}

	if diff := deep.Equal(readData, data); len(diff) > 0 {
		t.Errorf("Data read doesn't match what was written:")
		for _, l := range diff {
			t.Error(l)
		}
	}
}

func TestReadUnsetKeyVDefault(t *testing.T) {
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

	mountPath := "secret"

	kv := &KV{MountPoint: mountPath, Client: vaultClient, version: 2}
	_, _, err = kv.ReadLatest("unset/key")
	if err == nil {
		t.Errorf("no error returned for unset key")
	}
}
