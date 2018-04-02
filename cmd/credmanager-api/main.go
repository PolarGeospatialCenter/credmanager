package main

import (
	"log"
	"net/http"

	"github.com/PolarGeospatialCenter/credmanager/pkg/vaultstate"
	"github.com/PolarGeospatialCenter/inventory/pkg/inventory"
	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
)

func readConfig() *viper.Viper {
	cfg := viper.New()
	cfg.SetConfigName("credmanager")
	cfg.AddConfigPath(".")
	cfg.AddConfigPath("/etc/credmanager/")
	cfg.ReadInConfig()
	return cfg
}

func getConsulClient(cfg *viper.Viper) (*consul.Client, error) {
	if cfg.InConfig("consul") {
		cfg = cfg.Sub("consul")
	} else {
		cfg = viper.New()
	}

	config := consul.DefaultConfig()
	if cfg.InConfig("address") {
		config.Address = cfg.GetString("address")
	}
	if cfg.InConfig("token") {
		config.Token = cfg.GetString("token")
	}

	return consul.NewClient(config)
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

	h := NewCredmanagerHandler(consulStore, NewAppRoleSecretManager(vaultClient), vaultstate.NewVaultStateManager("nodes/bootable", vaultClient))
	http.Handle("/secret", h)
	log.Printf("Starting webserver on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
