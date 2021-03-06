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

	"github.com/PolarGeospatialCenter/credmanager/pkg/credentials"
	"github.com/PolarGeospatialCenter/vaulthelper/pkg/vaulthelper"
	vault "github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// Credential types manage a particular vault secret.  Manage should create/update
// the secret, then start a renewal process to keep the credential up to date.
// When stop is called the renewal process should stop.
type Credential interface {
	// Issues the credential, sets up a renewer, and starts it
	Initialize(*vault.Client) error
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

	credList, err := loadCredentialConfigs(viper.GetString("credential_config_dir"))
	if err != nil {
		log.Fatalf("Unable to load credential configurations: %v", err)
	}
	log.Printf("Loaded credential configurations: %v", credList)

	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = viper.GetString("vault.address")
	vaultConfig.Timeout = time.Second * 2
	vaultConfig.ConfigureTLS(&vault.TLSConfig{
		ClientCert: viper.GetString("vault.client_cert"),
		ClientKey:  viper.GetString("vault.client_key"),
		Insecure:   false,
	})
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Unable to create vault client %s\n", err)
	}

	tokenTimer := credentials.NewRenewTimer(0, 3*time.Hour, 5*time.Second, 10)

	var secret *vault.Secret
	for attempt := 0; attempt < 7; attempt++ {
		<-tokenTimer.C
		token, err := vaulthelper.NewDefaultChainProvider(vaultClient).RetrieveToken()
		if err != nil {
			log.Printf("Unable to retrieve token, retrying (attempt %d): %v", attempt, err)
			tokenTimer.FailReset(3 * time.Hour)
			continue
		}

		vaultClient.SetToken(token)

		// Renew so that we have a populated Auth struct in the secret.
		secret, err = vaultClient.Auth().Token().RenewSelf(0)
		if err != nil {
			log.Printf("Error renewing our own token, retrying (attempt %d): %v", attempt, err)
			secret = nil
			tokenTimer.FailReset(3 * time.Hour)
			continue
		}
		log.Printf("Renewed our vault token.")
		break
	}
	tokenTimer.Stop()

	if secret == nil {
		log.Fatalf("Unable to get a valid token.  Refusing to start.")
	}

	gracePeriod := 24 * time.Hour
	tokenRenewer, err := vaultClient.NewRenewer(&vault.RenewerInput{Secret: secret, Grace: gracePeriod})
	if err != nil {
		log.Fatalf("Error creating token renewer: %v", err)
	}

	go tokenRenewer.Renew()
	defer tokenRenewer.Stop()
	log.Printf("Started token renewer.")

	renewers := &credentials.RenewerMerger{}

	for _, credential := range credList {
		credErr := credential.Initialize(vaultClient)
		if credErr != nil {
			log.Printf("Unable to initialize credential %s: %v", credential, credErr)
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
				log.Printf("Got SIGTERM, exiting.")
				return
			case syscall.SIGINT:
				log.Printf("Got SIGINT, exiting.")
				return
			}
		case renewal := <-renewers.RenewCh():
			log.Printf("Renewal: %s", renewal)
		case err := <-renewers.DoneCh():
			switch err.(type) {
			case credentials.ErrMaxRetriesExceeded:
				log.Fatalf("Exiting: %v", err)
			default:
				log.Printf("Got error: %v", err)
			}
		case renewal := <-tokenRenewer.RenewCh():
			log.Printf("Renewed credmanager vault token: %v", renewal)
		case err := <-tokenRenewer.DoneCh():
			log.Printf("Error renewing credmanager vault token: %v", err)
			log.Fatalf("Unable to renew our own token, exiting.")
		}
	}
}
