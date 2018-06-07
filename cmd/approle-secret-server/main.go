package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"

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
	cfg.SetDefault("vault.kv_prefix", "secret")
	cfg.SetDefault("vault.kv_version", "1")
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

	kvPrefix := cfg.GetString("vault.kv_prefix")

	kvVersion, err := strconv.Atoi(cfg.GetString("vault.kv_version"))
	if err != nil {
		log.Fatalf("unable to parse vault.kv_version %s", cfg.GetString("vault.kv_version"))
	}

	h := NewCredmanagerHandler(NewAppRoleSecretManager(vaultClient),
		vaultstate.NewVaultStateManager("nodes/bootable", vaulthelper.NewKV(vaultClient, kvPrefix, kvVersion)))
	http.Handle("/secret", h)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := "healthy"
		if _, err := vaultClient.Auth().Token().LookupSelf(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			status = "expired or bad token"
		}
		w.Write([]byte(fmt.Sprintf("{\"status\": \"%s\"}", status)))
	})
	log.Printf("Starting webserver on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
