package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-test/deep"
	vault "github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v2"
)

const (
	testSSHCertPolicy = `path "ssh/sign/testhost" {
		capabilities = ["update"]
}`
)

func mountSSHBackend(vaultClient *vault.Client, name string) error {
	mount := &vault.MountInput{
		Type:        "ssh",
		Description: "SSH Key Signing",
		Config: vault.MountConfigInput{
			DefaultLeaseTTL: "86400",
			MaxLeaseTTL:     "86400",
			ForceNoCache:    true,
			PluginName:      "ssh",
		},
		Local:      true,
		PluginName: "ssh",
	}
	err := vaultClient.Sys().Mount(name, mount)
	if err != nil {
		return err
	}

	return generateSSHCA(vaultClient, name)
}

func generateSSHCA(vaultClient *vault.Client, sshMount string) error {
	r := vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/config/ca", sshMount))
	params := map[string]interface{}{
		"generate_signing_key": true,
	}

	body, err := json.Marshal(params)
	if err != nil {
		return err
	}

	r.Body = bytes.NewBuffer(body)

	response, err := vaultClient.RawRequest(r)
	if err != nil {
		return err
	}
	return response.Error()
}

func createSSHRole(vaultClient *vault.Client, sshMount string, roleName string) error {
	r := vaultClient.NewRequest("POST", fmt.Sprintf("/v1/%s/roles/%s", sshMount, roleName))
	params := map[string]interface{}{
		"name":                    roleName,
		"key_type":                "ca",
		"allow_host_certificates": true,
		"allowed_domains":         "local",
		"allow_subdomains":        true,
	}

	body, err := json.Marshal(params)
	if err != nil {
		return err
	}

	r.Body = bytes.NewBuffer(body)

	response, err := vaultClient.RawRequest(r)
	if err != nil {
		return err
	}
	return response.Error()
}

func TestSSHCertManage(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "sshcerttest")
	if err != nil {
		t.Fatalf("Unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	certFile, err := NewCredentialFile(filepath.Join(tempDir, "ssh.crt"), 0600, "", "")
	if err != nil {
		t.Fatalf("Unable to create credential file: %v", err)
	}

	cert := &SSHHostCertificate{
		PublicKeyFile:     "test_data/ssh_host_key.pub",
		CertificateFile:   certFile,
		BackendMountPoint: "ssh",
		RoleName:          "testhost",
		LeaseDuration:     1 * time.Second,
		ValidPrincipals:   []string{"foo.local", "bar.local"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	vaultConfig := RunVault(ctx)
	defer cancel()

	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	vaultClient.SetToken(vaultTestRootToken)

	time.Sleep(10 * time.Millisecond)
	err = mountSSHBackend(vaultClient, "ssh")
	if err != nil {
		t.Fatalf("Unable to mount ssh backend: %v", err)
	}

	err = createSSHRole(vaultClient, "ssh", "testhost")
	if err != nil {
		t.Fatalf("Unable to create test role on ssh backend: %v", err)
	}

	err = vaultClient.Sys().PutPolicy("test-ssh-node-cert", testSSHCertPolicy)
	if err != nil {
		t.Fatalf("Unable to create policy allowing cert issuance: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"test-ssh-node-cert"}})
	if err != nil {
		t.Fatalf("Unable to create token with cert policy: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	s, err := vaultClient.Auth().Token().LookupSelf()
	t.Log(s.Data["policies"])

	err = cert.Manage(vaultClient)
	if err != nil {
		t.Fatalf("Unable to start cert management process: %v", err)
	}

	info, err := os.Stat(certFile.Path())
	if err != nil && os.IsNotExist(err) {
		t.Fatalf("Certificate not written")
	} else if err != nil {
		t.Errorf("Unable to stat certificate file: %v", err)
	}

	if info.Mode() != 0600 {
		t.Errorf("Wrong mode set on certificate file: %s", info.Mode())
	}

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

func getTestSSHHostCertificateInfo() (*SSHHostCertificate, string) {
	certFile, _ := NewCredentialFile(filepath.Join("/test", "ssh.crt"), 0600, "", "")

	cert := &SSHHostCertificate{
		PublicKeyFile:     "test_data/ssh_host_key.pub",
		CertificateFile:   certFile,
		BackendMountPoint: "ssh",
		RoleName:          "testhost",
		LeaseDuration:     72 * time.Hour,
		ValidPrincipals:   []string{"foo.local", "bar.local"},
		Notifies:          "foo.service",
	}

	marhsaledYAML := `public_key_file: test_data/ssh_host_key.pub
certificate_file:
  path: /test/ssh.crt
  mode: 0600
vault_backend_mount: ssh
role: testhost
lifetime: 72h
valid_principals:
  - foo.local
  - bar.local
notifies: foo.service
required_policies:
  - test-ssh-node-cert
`
	return cert, marhsaledYAML
}

func TestSSHHostCertificateUnmarshalYAML(t *testing.T) {
	expected, testText := getTestSSHHostCertificateInfo()
	dst := &SSHHostCertificate{}

	err := yaml.Unmarshal([]byte(testText), dst)
	if err != nil {
		t.Fatalf("Unable to unmarshal: %v", err)
	}
	dst.CertificateFile.populateUserGroupData()

	if diff := deep.Equal(dst, expected); diff != nil {
		t.Errorf("Unmarshaled not equal to expected:")
		for _, d := range diff {
			t.Error(d)
		}
		t.FailNow()
	}

}
