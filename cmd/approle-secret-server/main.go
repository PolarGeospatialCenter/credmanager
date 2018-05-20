package main

import (
	"log"
	"net/http"

	"github.com/PolarGeospatialCenter/awstools/pkg/config"
	"github.com/PolarGeospatialCenter/credmanager/pkg/vaulthelper"
	"github.com/PolarGeospatialCenter/credmanager/pkg/vaultstate"
	vault "github.com/hashicorp/vault/api"
)

// ConfigurationStore interface
type ConfigurationStore interface {
	GetString(string) string
}

func readConfig() ConfigurationStore {
	cfg := config.NewParameterViper()
	cfg.SetConfigName("config")
	cfg.AddConfigPath(".")
	cfg.AddConfigPath("/etc/approle-secret-server/")
	cfg.ReadInConfig()
	return cfg
}

func getVaultClient(cfg ConfigurationStore) (*vault.Client, error) {
	config := vault.DefaultConfig()
	configuredVaultAddress := cfg.GetString("vault.address")
	if configuredVaultAddress != "" {
		config.Address = configuredVaultAddress
	}

	vaultClient, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	configuredVaultToken := cfg.GetString("vault.token")
	if configuredVaultToken != "" {
		vaultClient.SetToken(configuredVaultToken)
	}
	return vaultClient, nil
}

func main() {
	cfg := readConfig()

	vaultClient, err := getVaultClient(cfg)
	if err != nil {
		log.Fatalf("Unable to connect to vault: %v", err)
	}

	h := NewCredmanagerHandler(NewAppRoleSecretManager(vaultClient), vaultstate.NewVaultStateManager("nodes/bootable", vaulthelper.NewKV(vaultClient, "secret", 2)))
	http.Handle("/secret", h)
	log.Printf("Starting webserver on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
