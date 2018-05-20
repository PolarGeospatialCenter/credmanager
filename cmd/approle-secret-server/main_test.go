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

func TestGetVaultClientWithEnvToken(t *testing.T) {
	testConfigWithoutToken := `vault:
  address: https://localhost:8200
`
	os.Setenv("VAULT_TOKEN", "fd239745-f89b-eeee-670e-74cd2865ba32")
	cfg := viper.New()
	cfg.SetConfigType("yaml")
	cfg.ReadConfig(bytes.NewBufferString(testConfigWithoutToken))
	vaultClient, err := getVaultClient(cfg)
	if err != nil {
		t.Errorf("Unable to parse config without token: %v", err)
	}

	if vaultClient.Address() != "https://localhost:8200" {
		t.Errorf("Wrong vault address used: %s", vaultClient.Address())
	}

	if vaultClient.Token() != "fd239745-f89b-eeee-670e-74cd2865ba32" {
		t.Errorf("Wrong vault token used: %s", vaultClient.Token())
	}

}

func TestGetVaultClientWithEnv(t *testing.T) {
	testConfigWithoutToken := ``
	os.Setenv("VAULT_ADDR", "https://localhost:8201")
	defer os.Unsetenv("VAULT_ADDR")
	os.Setenv("VAULT_TOKEN", "fd239745-f89b-eeee-670e-74cd2865ba32")
	defer os.Unsetenv("VAULT_TOKEN")
	cfg := viper.New()
	cfg.SetConfigType("yaml")
	cfg.ReadConfig(bytes.NewBufferString(testConfigWithoutToken))
	vaultClient, err := getVaultClient(cfg)
	if err != nil {
		t.Errorf("Unable to parse config without token: %v", err)
	}

	if vaultClient.Address() != "https://localhost:8201" {
		t.Errorf("Wrong vault address used: %s", vaultClient.Address())
	}

	if vaultClient.Token() != "fd239745-f89b-eeee-670e-74cd2865ba32" {
		t.Errorf("Wrong vault token used: %s", vaultClient.Token())
	}

}
