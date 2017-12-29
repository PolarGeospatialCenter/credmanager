package main

import (
	"log"
	"net/http"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
)

func readConfig() *viper.Viper {
	cfg := viper.New()
	cfg.SetConfigName("credmanager")
	cfg.AddConfigPath(".")
	cfg.ReadInConfig()
	return cfg
}

func getConsulClient(cfg *viper.Viper) (*consul.Client, error) {
	config := consul.DefaultConfig()
	config.Address = cfg.GetString("consul.address")
	config.Token = cfg.GetString("consul.token")
	return consul.NewClient(config)
}

func getVaultClient(cfg *viper.Viper) (*vault.Client, error) {
	config := vault.DefaultConfig()
	config.Address = cfg.GetString("vault.address")
	vaultClient, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	vaultClient.SetToken(cfg.GetString("vault.token"))
	return vaultClient, nil
}

func main() {
	cfg := readConfig()

	consulClient, err := getConsulClient(cfg)
	if err != nil {
		log.Fatalf("Unable to connect to consul: %v", err)
	}

	vaultClient, err := getVaultClient(cfg)
	if err != nil {
		log.Fatalf("Unable to connect to vault: %v", err)
	}

	consulStore, err := inventory.NewConsulStore(consulClient, inventory.DefaultConsulInventoryBase)
	if err != nil {
		log.Fatalf("Unable to connect to consul inventory: %v", err)
	}

	h := NewCredmanagerHandler(consulStore, consulClient, NewTokenManager(vaultClient, cfg.GetString("vault.policy.template")))
	http.Handle("/token", h)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
