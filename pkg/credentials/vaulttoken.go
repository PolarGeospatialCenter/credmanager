package credentials

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type VaultToken struct {
	Policies           []string        `yaml:"policies"`
	TokenCreateRole    string          `yaml:"creation_role"`
	TokenFile          *CredentialFile `yaml:"token_file"`
	MaxRenewalInterval time.Duration   `yaml:"max_renew"`
	renewer            *CredentialRenewer
	vaultClient        *vault.Client
}

func (t *VaultToken) Initialize(vaultClient *vault.Client) error {
	t.vaultClient = vaultClient
	if t.MaxRenewalInterval <= 0 {
		// No renewal interval set, must get token now to update default interval
		err := t.getNewToken()
		if err != nil {
			// unable to issue a token now, no renewal interval known
			t.MaxRenewalInterval = time.Second * 10
		}
	}

	t.renewer = NewCredentialRenewer(t, nil)
	t.renewer.Renew()
	return nil
}

func (t *VaultToken) updateRenewalInterval(ttl int) {
	log.Printf("Updating renewal interval on token to: %ds", ttl)
	if 0 < ttl && (ttl < int(t.MaxRenewalInterval.Seconds()) || t.MaxRenewalInterval.Seconds() == 0) {
		t.MaxRenewalInterval = time.Duration(ttl) * time.Second
	}
}

func (t *VaultToken) getNewToken() error {
	tokenRequest := &vault.TokenCreateRequest{Policies: t.Policies}
	if t.MaxRenewalInterval.Seconds() > 0 {
		tokenRequest.TTL = fmt.Sprintf("%d", int(t.MaxRenewalInterval.Seconds()))
	}
	secret, err := t.vaultClient.Auth().Token().CreateWithRole(tokenRequest, t.TokenCreateRole)
	if err != nil {
		return err
	}
	t.updateRenewalInterval(secret.Auth.LeaseDuration)
	return t.TokenFile.Write(secret.Auth.ClientToken)
}

func (t *VaultToken) Renew() error {
	existingToken, err := t.TokenFile.Read()
	if err != nil && os.IsExist(err) {
		return err
	}

	if existingToken != "" {
		newSecret, err := t.vaultClient.Auth().Token().RenewTokenAsSelf(existingToken, int(t.MaxRenewalInterval.Seconds()))
		if err != nil {
			return fmt.Errorf("unable to renew %s: %v", t, err)
		}
		t.updateRenewalInterval(newSecret.Auth.LeaseDuration)
		return nil
	}

	return t.getNewToken()
}

func (t *VaultToken) Stop() {
	t.renewer.Stop()
}

func (t *VaultToken) MaxRenewInterval() time.Duration {
	return t.MaxRenewalInterval
}

func (t *VaultToken) String() string {
	return fmt.Sprintf("Vault Token for role '%s' stored at '%s'", strings.Join(t.Policies, " "), t.TokenFile.Path())
}

func (t *VaultToken) Renewer() Renewer {
	return t.renewer
}
