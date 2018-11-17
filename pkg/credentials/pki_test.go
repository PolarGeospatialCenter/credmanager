package credentials

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaulttest "github.com/PolarGeospatialCenter/dockertest/pkg/vault"
	"github.com/go-test/deep"
	vault "github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v2"
)

const (
	testCertPolicy = `path "pki/issue/testhost" {
		capabilities = ["update"]
}`
)

func mountPKIBackend(vaultClient *vault.Client, name string) error {
	mount := &vault.MountInput{
		Type:        "pki",
		Description: "PKI CA",
		Config: vault.MountConfigInput{
			DefaultLeaseTTL: "86400",
			MaxLeaseTTL:     "86400",
			ForceNoCache:    true,
			PluginName:      "pki",
		},
		Local:      true,
		PluginName: "pki",
	}
	err := vaultClient.Sys().Mount(name, mount)
	if err != nil {
		return err
	}

	err = generatePKICA(vaultClient, name)
	if err != nil {
		return err
	}

	return configPKIUrls(vaultClient, name)
}

func generatePKICA(vaultClient *vault.Client, pkiMount string) error {
	r := vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/root/generate/internal", pkiMount))
	params := map[string]interface{}{
		"common_name": "ca.local",
		"ttl":         "1h",
	}

	r.SetJSONBody(params)

	response, err := vaultClient.RawRequest(r)
	if err != nil {
		return err
	}
	return response.Error()
}

func configPKIUrls(vaultClient *vault.Client, pkiMount string) error {
	r := vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/config/urls", pkiMount))
	params := map[string]interface{}{
		"issuing_certificates":    fmt.Sprintf("%s/v1/pki/ca", vaultClient.Address()),
		"crl_distribution_points": fmt.Sprintf("%s/v1/pki/crl", vaultClient.Address()),
	}

	r.SetJSONBody(params)

	response, err := vaultClient.RawRequest(r)
	if err != nil {
		return err
	}
	return response.Error()
}

func createPKIRole(vaultClient *vault.Client, pkiMount string, roleName string) error {
	r := vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/roles/%s", pkiMount, roleName))
	params := map[string]interface{}{
		"allowed_domains":  "local",
		"allow_subdomains": true,
		"max_ttl":          "30m",
	}

	r.SetJSONBody(params)

	response, err := vaultClient.RawRequest(r)
	if err != nil {
		return err
	}
	return response.Error()
}

func TestPKICertManage(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "pkicerttest")
	if err != nil {
		t.Fatalf("Unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certFile, err := NewCredentialFile(filepath.Join(tempDir, "pki.crt"), 0600, "", "")
	if err != nil {
		t.Fatalf("Unable to create credential file: %v", err)
	}

	keyFile, err := NewCredentialFile(filepath.Join(tempDir, "pki.key"), 0600, "", "")
	if err != nil {
		t.Fatalf("Unable to create credential file: %v", err)
	}

	caFile, err := NewCredentialFile(filepath.Join(tempDir, "ca.crt"), 0600, "", "")
	if err != nil {
		t.Fatalf("Unable to create credential file: %v", err)
	}

	cert := &PKICertificate{
		PrivateKeyFile:                      keyFile,
		CertificateFile:                     certFile,
		CertificateAuthorityCertificateFile: caFile,
		CommonName:                          "test.local",
		AlternativeNames:                    []string{"foo.local", "bar.local"},
		IPSubjectAlternativeNames:           []string{"10.2.0.1"},
		BackendMountPoint:                   "pki",
		RoleName:                            "testhost",
		LeaseDuration:                       2 * time.Second,
	}

	ctx := context.Background()
	vaultInstance, err := vaulttest.Run(ctx)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	defer vaultInstance.Stop(ctx)

	vaultClient, err := vault.NewClient(vaultInstance.Config())
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}

	vaultClient.SetToken(vaultInstance.RootToken())

	err = mountPKIBackend(vaultClient, "pki")
	if err != nil {
		t.Fatalf("Unable to mount pki backend: %v", err)
	}

	err = createPKIRole(vaultClient, "pki", "testhost")
	if err != nil {
		t.Fatalf("Unable to create test role on pki backend: %v", err)
	}

	err = vaultClient.Sys().PutPolicy("test-pki-node-cert", testCertPolicy)
	if err != nil {
		t.Fatalf("Unable to create policy allowing cert issuance: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"test-pki-node-cert"}})
	if err != nil {
		t.Fatalf("Unable to create token with cert policy: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	err = cert.Initialize(vaultClient)
	if err != nil {
		t.Fatalf("Unable to start cert management process: %v", err)
	}

	err = cert.Issue()
	if err != nil {
		t.Fatalf("Unable to issue initial credential: %v", err)
	}

	log.Printf("Issued initial credential returned")

	info, err := os.Stat(certFile.Path())
	if err != nil && os.IsNotExist(err) {
		t.Fatalf("Certificate not written")
	} else if err != nil {
		t.Errorf("Unable to stat certificate file: %v", err)
	}

	if info.Mode() != 0600 {
		t.Errorf("Wrong mode set on certificate file: %s", info.Mode())
	}

	log.Printf("Waiting for renewal...")
	oldContents, _ := certFile.Read()
	for renewCount := 0; renewCount < 2; renewCount++ {
		select {
		case renewal := <-cert.Renewer().RenewCh():
			t.Logf("%s", renewal)
			newContents, _ := certFile.Read()
			if oldContents == newContents {
				t.Errorf("Renew of certificate failed")
			}
			oldContents = newContents
		case err := <-cert.Renewer().DoneCh():
			if err != nil {
				t.Errorf("Error renewing cert: %v", err)
			}
		}
	}

	cert.Stop()
}

func getTestPKICertificateInfo() (*PKICertificate, string) {
	certFile, _ := NewCredentialFile(filepath.Join("/test", "host.crt"), 0644, "", "")
	caFile, _ := NewCredentialFile(filepath.Join("/test", "ca.crt"), 0644, "", "")
	keyFile, _ := NewCredentialFile(filepath.Join("/test", "host.key"), 0600, "", "")

	cert := &PKICertificate{
		PrivateKeyFile:                      keyFile,
		CertificateAuthorityCertificateFile: caFile,
		CertificateFile:                     certFile,
		RoleName:                            "testhost",
		CommonName:                          "foo.local",
		AlternativeNames:                    []string{"bar.local", "baz.local"},
		IPSubjectAlternativeNames:           []string{"10.28.0.1", "10.28.1.1"},
		LeaseDuration:                       72 * time.Hour,
		BackendMountPoint:                   "pki",
		Notifies:                            "foo.service",
	}

	marhsaledYAML := `certificate_file:
  path: /test/host.crt
  mode: 0644
private_key_file:
  path: /test/host.key
  mode: 0600
ca_cert_file:
  path: /test/ca.crt
  mode: 0644
vault_backend_mount: pki
role: testhost
common_name: foo.local
alternative_names:
  - bar.local
  - baz.local
ip_sans:
  - 10.28.0.1
  - 10.28.1.1
lifetime: 72h
notifies: foo.service
required_policies:
  - test-pki-node-cert
`
	return cert, marhsaledYAML
}

func TestPKICertificateUnmarshalYAML(t *testing.T) {
	expected, testText := getTestPKICertificateInfo()
	dst := &PKICertificate{}

	err := yaml.Unmarshal([]byte(testText), dst)
	if err != nil {
		t.Fatalf("Unable to unmarshal: %v", err)
	}
	dst.CertificateFile.populateUserGroupData()
	dst.CertificateAuthorityCertificateFile.populateUserGroupData()
	dst.PrivateKeyFile.populateUserGroupData()

	if diff := deep.Equal(dst, expected); diff != nil {
		t.Errorf("Unmarshaled not equal to expected:")
		for _, d := range diff {
			t.Error(d)
		}
		t.FailNow()
	}

}
