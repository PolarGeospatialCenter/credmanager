package credentials

import (
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// SSHHostCertificate is a credential type for ssh host certificate creation
type SSHHostCertificate struct {
	PublicKeyFile     string          `yaml:"public_key_file"`
	CertificateFile   *CredentialFile `yaml:"certificate_file"`
	BackendMountPoint string          `yaml:"vault_backend_mount"`
	LeaseDuration     time.Duration   `yaml:"lifetime"`
	RoleName          string          `yaml:"role"`
	ValidPrincipals   []string        `yaml:"valid_principals"`
	Notifies          string          `yaml:"notifies"`
	vaultClient       *vault.Client
	renewer           *CredentialRenewer
}

func (s *SSHHostCertificate) Manage(vaultClient *vault.Client) error {
	s.vaultClient = vaultClient
	secret, err := s.sign()
	if err != nil {
		return err
	}
	s.write(secret)

	var postAction PostRenewAction
	if s.Notifies != "" {
		postAction = &ReloadOrRestartSystemdUnit{UnitName: s.Notifies}
	}
	s.renewer = NewCredentialRenewer(s, postAction)
	s.renewer.Renew()

	return nil
}

func (s *SSHHostCertificate) Renew() error {
	secret, err := s.sign()
	if err != nil {
		return err
	}
	s.write(secret)
	return nil
}

func (s *SSHHostCertificate) MaxRenewInterval() time.Duration {
	return s.LeaseDuration
}

func (s *SSHHostCertificate) Stop() {
	s.renewer.Stop()
}

func (s *SSHHostCertificate) Renewer() Renewer {
	return s.renewer
}

// signs the public key and writes the result to file, returning the secret and any errors
func (s *SSHHostCertificate) sign() (*vault.Secret, error) {

	publicKey, err := ioutil.ReadFile(s.PublicKeyFile)
	if err != nil {
		return nil, err
	}

	keyData := make(map[string]interface{})
	keyData["public_key"] = string(publicKey)
	keyData["cert_type"] = "host"
	keyData["valid_principals"] = strings.Join(s.ValidPrincipals, ",")
	secret, err := s.vaultClient.SSHWithMountPoint(s.BackendMountPoint).SignKey(s.RoleName, keyData)
	if err != nil {
		return nil, err
	}
	return secret, err
}

func (s *SSHHostCertificate) write(secret *vault.Secret) error {
	return s.CertificateFile.Write(secret.Data["signed_key"].(string))
}

func (s *SSHHostCertificate) String() string {
	return fmt.Sprintf("SSH Host Certificate Credential -- PublicKey: %s -- LeaseDuration: %s", s.PublicKeyFile, s.LeaseDuration)
}
