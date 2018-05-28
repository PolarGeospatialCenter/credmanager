package main

import (
	"fmt"
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
	log.Printf("Loaded vault address from configuration: %s", configuredVaultAddress)
	if configuredVaultAddress != "" {
		config.Address = configuredVaultAddress
	}

	vaultClient, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	configuredVaultToken := cfg.GetString("vault.token")
	if configuredVaultToken != "" {
		log.Printf("Found vault token in configuration file or parameter store, using")
		vaultClient.SetToken(configuredVaultToken)
	} else if vaultClient.Token() == "" {
		log.Printf("No token configuration found.  Falling back to using ec2 instance profile.")
		secret, err := vaulthelper.LoginWithEC2InstanceProfile(vaultClient, cfg.GetString("vault.role"), "")
		if err != nil {
			return nil, fmt.Errorf("unable to authenticate using instance profile: %v", err)
		}
		vaultClient.SetToken(secret.Auth.ClientToken)
	}
	return vaultClient, nil
}

func main() {
	cfg := readConfig()

	vaultClient, err := getVaultClient(cfg)
	if err != nil {
		log.Fatalf("Unable to connect to vault: %v", err)
	}

	secret, err := vaultClient.Auth().Token().LookupSelf()
	if err != nil {
		log.Fatalf("unable to lookup our own token for renewal setup: %v", err)
	}

	renewable, err := secret.TokenIsRenewable()
	if err == nil && renewable {
		renewer, err := vaultClient.NewRenewer(&vault.RenewerInput{Secret: secret})
		if err != nil {
			log.Fatalf("token is renewable, but setting up a renewer failed: %v", err)
		}
		go renewer.Renew()
		defer renewer.Stop()
	} else if err != nil {
		log.Printf("unable to determine renability of token: %v", err)
	}

	h := NewCredmanagerHandler(NewAppRoleSecretManager(vaultClient), vaultstate.NewVaultStateManager("nodes/bootable", vaulthelper.NewKV(vaultClient, "secret", 1)))
	http.Handle("/secret", h)
	log.Printf("Starting webserver on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
