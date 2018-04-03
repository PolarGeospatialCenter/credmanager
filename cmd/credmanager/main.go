package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	credmanager "github.com/PolarGeospatialCenter/credmanager/pkg/client"
	"github.com/PolarGeospatialCenter/credmanager/pkg/credentials"
	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// Credential types manage a particular vault secret.  Manage should create/update
// the secret, then start a renewal process to keep the credential up to date.
// When stop is called the renewal process should stop.
type Credential interface {
	// Issues the credential, sets up a renewer, and starts it
	Manage(*vault.Client) error
	Stop()
	Renewer() credentials.Renewer
	fmt.Stringer
}

// CredentialConfigFile describes the layout of a credential configuration file
// found in the configuration directory.
type CredentialConfigFile struct {
	SSH      []*credentials.SSHHostCertificate `mapstructure:"ssh"`
	Pki      []*credentials.PKICertificate     `mapstructure:"pki"`
	Vault    []*credentials.SSHHostCertificate `mapstructure:"vault"`
	Template []*credentials.CredentialTemplate `mapstructure:"template"`
}

// loads all credential configs found in config dir and merges them into one list
func loadCredentialConfigs(configDir string) ([]Credential, error) {
	var creds []Credential
	files, err := ioutil.ReadDir(configDir)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if f.IsDir() || (filepath.Ext(f.Name()) != ".yml" && filepath.Ext(f.Name()) != ".yaml") {
			log.Printf("Ignoring: %s", f.Name())
			continue
		}

		contents, readErr := ioutil.ReadFile(filepath.Join(configDir, f.Name()))
		if readErr != nil {
			return nil, readErr
		}

		config := &CredentialConfigFile{}
		unmarshalErr := yaml.Unmarshal(contents, config)
		if unmarshalErr != nil {
			return nil, fmt.Errorf("%s -- %v", f.Name(), unmarshalErr)
		}

		for _, item := range config.SSH {
			creds = append(creds, item)
		}
		for _, item := range config.Pki {
			creds = append(creds, item)
		}
		for _, item := range config.Vault {
			creds = append(creds, item)
		}
		for _, item := range config.Template {
			creds = append(creds, item)
		}
	}
	return creds, nil
}

func main() {
	viper.SetDefault("vault.address", "http://127.0.0.1:8200")
	if hostname, err := os.Hostname(); err == nil {
		viper.SetDefault("hostname", hostname)
	}

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/credmanager")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Unable to read config file: %v", err)
	}

	credManager := &credmanager.CredManagerClient{}
	err = viper.UnmarshalKey("credmanager", credManager)
	if err != nil {
		log.Fatalf("Unable to read credmanager section of config file: %v", err)
	}

	credList, err := loadCredentialConfigs(viper.GetString("credential_config_dir"))
	if err != nil {
		log.Fatalf("Unable to load credential configurations: %v", err)
	}
	fmt.Println(credList)

	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = viper.GetString("vault.address")
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Unable to create vault client %s\n", err)
	}

	_, err = vaultClient.Sys().Health()
	if err != nil {
		log.Fatalf("Unable to check health of vault %s\n", err)
	}

	token, err := credManager.GetToken(vaultClient)
	if err != nil {
		log.Fatalf("Unable to get or load token: %v", err)
	}

	vaultClient.SetToken(token)

	secret, err := vaultClient.Auth().Token().LookupSelf()
	if err != nil {
		log.Fatalf("Error looking up our own token: %v", err)
	}

	gracePeriod := 24 * time.Hour
	renewer, err := vaultClient.NewRenewer(&vault.RenewerInput{Secret: secret, Grace: gracePeriod})
	if err != nil {
		log.Fatalf("Error creating token renewer: %v", err)
	}

	renewer.Renew()

	renewers := &credentials.RenewerMerger{}

	for _, credential := range credList {
		credErr := credential.Manage(vaultClient)
		if credErr != nil {
			log.Printf("Unable to issue credential %s: %v", credential, credErr)
		}
		renewers.AddRenewer(credential.Renewer())
		defer credential.Stop()
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case signal := <-signalChan:
			switch signal {
			case syscall.SIGTERM:
				return
			case syscall.SIGINT:
				return
			}
		case renewal := <-renewers.RenewCh():
			log.Printf("Renewal: %s", renewal)
		case err := <-renewers.DoneCh():
			log.Printf("Got error: %v", err)
		}
	}
}