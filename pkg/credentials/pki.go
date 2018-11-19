package credentials

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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
	configuredDuration                  time.Duration
}

func (p *PKICertificate) Initialize(vaultClient *vault.Client) error {
	p.vaultClient = vaultClient
	p.configuredDuration = p.LeaseDuration

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
	return p.sign()
}

func (p *PKICertificate) Stop() {
	log.Printf("Entering stop")
	p.renewer.Stop()
	log.Printf("Exiting stop")
}

func (p *PKICertificate) Renewer() Renewer {
	return p.renewer
}

func (p *PKICertificate) sign() error {
	keyBytes, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("error generating key: %v", err)
	}
	keyBytesPem := bytes.NewBuffer([]byte{})
	err = pem.Encode(keyBytesPem, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keyBytes)})
	if err != nil {
		return fmt.Errorf("error marshaling private key")
	}

	subj := pkix.Name{}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return fmt.Errorf("error generating key: %v", err)
	}

	csrBytesPem := bytes.NewBuffer([]byte{})
	pem.Encode(csrBytesPem, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	request := p.vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/sign/%s", p.BackendMountPoint, p.RoleName))
	pki_request := make(map[string]interface{})
	pki_request["common_name"] = p.CommonName
	pki_request["alt_names"] = strings.Join(p.AlternativeNames, ",")
	pki_request["ip_sans"] = strings.Join(p.IPSubjectAlternativeNames, ",")
	if p.configuredDuration != time.Duration(0) {
		pki_request["ttl"] = int64(p.configuredDuration.Seconds())
	}
	pki_request["csr"] = string(csrBytesPem.Bytes())
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
	expiration, ok := data["expiration"].(json.Number)
	if ok {
		expiresAt, err := expiration.Int64()
		if err != nil {
			return fmt.Errorf("error parsing certificate expiration time: %v", err)
		}

		p.LeaseDuration = time.Until(time.Unix(expiresAt, 0))
	}

	err = p.CertificateAuthorityCertificateFile.Write(data["issuing_ca"].(string))
	if err != nil {
		return err
	}

	err = p.CertificateFile.Write(data["certificate"].(string))
	if err != nil {
		return err
	}

	err = p.PrivateKeyFile.Write(string(keyBytesPem.Bytes()))
	if err != nil {
		return err
	}

	return nil
}

func (p *PKICertificate) issue() error {
	request := p.vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/issue/%s", p.BackendMountPoint, p.RoleName))
	pki_request := make(map[string]interface{})
	pki_request["common_name"] = p.CommonName
	pki_request["alt_names"] = strings.Join(p.AlternativeNames, ",")
	pki_request["ip_sans"] = strings.Join(p.IPSubjectAlternativeNames, ",")
	if p.configuredDuration != time.Duration(0) {
		pki_request["ttl"] = int64(p.configuredDuration.Seconds())
	}
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
	expiration, ok := data["expiration"].(json.Number)
	if ok {
		expiresAt, err := expiration.Int64()
		if err != nil {
			return fmt.Errorf("error parsing certificate expiration time: %v", err)
		}

		p.LeaseDuration = time.Until(time.Unix(expiresAt, 0))
	}

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
