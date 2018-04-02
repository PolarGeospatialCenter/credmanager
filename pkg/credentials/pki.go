package credentials

import (
	"fmt"
	"log"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type PKICertificate struct {
	PrivateKeyFile                      *CredentialFile `yaml:"private_key_file"`
	CertificateFile                     *CredentialFile `yaml:"certificate_file"`
	CertificateAuthorityCertificateFile *CredentialFile `yaml:"ca_cert_file"`
	RoleName                            string          `yaml:"role"`
	CommonName                          string          `yaml:"common_name"`
	AlternativeNames                    []string        `yaml:"alternative_names"`
	IPSubjectAlternativeNames           []string        `yaml:"ip_sans"`
	LeaseDuration                       time.Duration   `yaml:"lifetime"`
	BackendMountPoint                   string          `yaml:"vault_backend_mount"`
	Notifies                            string          `yaml:"notifies"`
	vaultClient                         *vault.Client
	renewer                             *CredentialRenewer
}

func (p *PKICertificate) Manage(vaultClient *vault.Client) error {
	p.vaultClient = vaultClient
	err := p.issue()
	if err != nil {
		return err
	}

	var postAction PostRenewAction
	if p.Notifies != "" {
		postAction = &ReloadOrRestartSystemdUnit{UnitName: p.Notifies}
	}
	p.renewer = NewCredentialRenewer(p, postAction)
	p.renewer.Renew()
	return nil
}

func (p *PKICertificate) MaxRenewInterval() time.Duration {
	return p.LeaseDuration
}

func (p *PKICertificate) Renew() error {
	return p.issue()
}

func (p *PKICertificate) Stop() {
	log.Printf("Entering stop")
	p.renewer.Stop()
	log.Printf("Exiting stop")
}

func (p *PKICertificate) Renewer() Renewer {
	return p.renewer
}

func (p *PKICertificate) issue() error {
	request := p.vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/issue/%s", p.BackendMountPoint, p.RoleName))
	pki_request := make(map[string]interface{})
	pki_request["common_name"] = p.CommonName
	pki_request["alt_names"] = strings.Join(p.AlternativeNames, ",")
	pki_request["ip_sans"] = strings.Join(p.IPSubjectAlternativeNames, ",")
	request.SetJSONBody(pki_request)
	response, err := p.vaultClient.RawRequest(request)
	if err != nil {
		return err
	}

	if response.Error() != nil {
		return response.Error()
	}

	output := make(map[string]interface{})
	if err = response.DecodeJSON(&output); err != nil {
		return err
	}
	data := output["data"].(map[string]interface{})
	err = p.CertificateAuthorityCertificateFile.Write(data["issuing_ca"].(string))
	if err != nil {
		return err
	}

	err = p.CertificateFile.Write(data["certificate"].(string))
	if err != nil {
		return err
	}

	err = p.PrivateKeyFile.Write(data["private_key"].(string))
	if err != nil {
		return err
	}

	return nil
}

func (p *PKICertificate) String() string {
	return fmt.Sprintf("PKI Certificate for %s", p.CommonName)
}
