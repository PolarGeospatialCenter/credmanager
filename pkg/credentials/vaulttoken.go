package credentials

import (
	"fmt"
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

func (t *VaultToken) Manage(vaultClient *vault.Client) error {
	t.vaultClient = vaultClient
	err := t.Issue()
	if err != nil {
		return err
	}

	t.renewer = NewCredentialRenewer(t, nil)
	t.renewer.Renew()
	return nil
}

func (t *VaultToken) updateRenewalInterval(ttl int) {
	if 0 < ttl && (ttl < int(t.MaxRenewalInterval.Seconds()) || t.MaxRenewalInterval.Seconds() == 0) {
		t.MaxRenewalInterval = time.Duration(ttl) * time.Second
	}
}

func (t *VaultToken) Issue() error {
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

	return fmt.Errorf("no valid token found to renew")
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
