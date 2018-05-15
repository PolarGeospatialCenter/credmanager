package main

import (
	"log"
	"net/http"

	"github.com/PolarGeospatialCenter/credmanager/pkg/vaultstate"
	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
)

func readConfig() *viper.Viper {
	cfg := viper.New()
	cfg.SetConfigName("config")
	cfg.AddConfigPath(".")
	cfg.AddConfigPath("/etc/approle-secret-server/")
	cfg.ReadInConfig()
	return cfg
}

func getVaultClient(cfg *viper.Viper) (*vault.Client, error) {
	if cfg.InConfig("vault") {
		cfg = cfg.Sub("vault")
	} else {
		cfg = viper.New()
	}

	config := vault.DefaultConfig()
	if cfg.InConfig("address") {
		config.Address = cfg.GetString("address")
	}

	vaultClient, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	if cfg.InConfig("token") {
		vaultClient.SetToken(cfg.GetString("token"))
	}
	return vaultClient, nil
}

func main() {
	cfg := readConfig()

	vaultClient, err := getVaultClient(cfg)
	if err != nil {
		log.Fatalf("Unable to connect to vault: %v", err)
	}

	h := NewCredmanagerHandler(NewAppRoleSecretManager(vaultClient), vaultstate.NewVaultStateManager("nodes/bootable", vaultClient))
	http.Handle("/secret", h)
	log.Printf("Starting webserver on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
