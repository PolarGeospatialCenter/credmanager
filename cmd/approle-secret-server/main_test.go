package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestGetVaultClientWithConfigToken(t *testing.T) {
	testConfigWithToken := `vault:
  address: https://localhost:8200
  token: fd239745-f89b-6669-670e-74cd2865ba32
`
	os.Unsetenv("VAULT_TOKEN")
	cfg := viper.New()
	cfg.SetConfigType("yaml")
	err := cfg.ReadConfig(bytes.NewBufferString(testConfigWithToken))
	if err != nil {
		t.Fatalf("Unable to read config: %v", err)
	}

	vaultClient, err := getVaultClient(cfg)
	if err != nil {
		t.Errorf("Unable to parse config with token: %v", err)
	}

	if vaultClient.Address() != "https://localhost:8200" {
		t.Errorf("Wrong vault address used: %s", vaultClient.Address())
	}

	if vaultClient.Token() != "fd239745-f89b-6669-670e-74cd2865ba32" {
		t.Errorf("Wrong vault token used: %s", vaultClient.Token())
	}
}
