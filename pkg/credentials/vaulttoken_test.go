package credentials

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaulttest "github.com/PolarGeospatialCenter/dockertest/pkg/vault"
	"github.com/go-test/deep"
	vault "github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v2"
)

var (
	issuerPolicy = `path "auth/token/create/test-issuer" {
  capabilities = ["update"]
}`
	// Role used to issue tokens.  Setting the period to 1 forces the ttl to 1s for the tokens.
	issuerRole = map[string]interface{}{
		"allowed_policies": "test-policy",
		"explicit_max_ttl": 0,
		"name":             "test-issuer",
		"orphan":           false,
		"period":           1,
		"renewable":        true,
	}
	testPolicy = `path "kv/test/*" {
    capabilities = ["read"]
    }`
)

func createVaultTokenRole(vaultClient *vault.Client, roleName string, roleData map[string]interface{}) error {
	r := vaultClient.NewRequest("POST", fmt.Sprintf("/v1/auth/token/roles/%s", roleName))
	r.SetJSONBody(roleData)
	response, err := vaultClient.RawRequest(r)
	if err != nil {
		return err
	}
	if response.Error() != nil {
		return response.Error()
	}
	return nil
}

func TestVaultTokenManage(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "tokentest")
	if err != nil {
		t.Fatalf("Unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tokenFile, err := NewCredentialFile(filepath.Join(tempDir, "token"), 0600, "", "")
	if err != nil {
		t.Fatalf("Unable to create credential file: %v", err)
	}

	token := &VaultToken{
		Policies:        []string{"test-policy"},
		TokenCreateRole: issuerRole["name"].(string),
		TokenFile:       tokenFile,
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

	vaultTestRootToken := vaultInstance.RootToken()
	vaultClient.SetToken(vaultTestRootToken)

	err = vaultClient.Sys().PutPolicy("token-issuer", issuerPolicy)
	if err != nil {
		t.Fatalf("Unable to create issuer policy in vault: %v", err)
	}

	err = createVaultTokenRole(vaultClient, issuerRole["name"].(string), issuerRole)
	if err != nil {
		t.Fatalf("Unable to create issuer role in vault: %v", err)
	}

	err = vaultClient.Sys().PutPolicy("test-policy", testPolicy)
	if err != nil {
		t.Fatalf("Unable to create test policy in vault: %v", err)
	}

	issuerSecret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{})
	if err != nil {
		t.Fatalf("Unable to create issuer token: %v", err)
	}

	vaultClient.SetToken(issuerSecret.Auth.ClientToken)

	err = token.Initialize(vaultClient)
	if err != nil {
		t.Fatalf("Unable to start token management process: %v", err)
	}

	<-token.Renewer().RenewCh()

	info, err := os.Stat(tokenFile.Path())
	if err != nil && os.IsNotExist(err) {
		t.Fatalf("Certificate not written")
	} else if err != nil {
		t.Errorf("Unable to stat certificate file: %v", err)
	}

	if info.Mode() != 0600 {
		t.Errorf("Wrong mode set on certificate file: %s", info.Mode())
	}

	if token.MaxRenewInterval() != time.Duration(issuerRole["period"].(int))*time.Second {
		t.Errorf("Wrong token renew interval")
	}

	for renewCount := 0; renewCount < 2; renewCount++ {
		select {
		case renewal := <-token.Renewer().RenewCh():
			t.Logf("%s", renewal)
		case err := <-token.Renewer().DoneCh():
			if err != nil {
				t.Errorf("Error renewing token: %v", err)
			}
		}
	}

	token.Stop()
}

func getTestVaultTokenInfo() (*VaultToken, string) {
	tokenFile, _ := NewCredentialFile(filepath.Join("/test", "token"), 0600, "", "")

	cert := &VaultToken{
		TokenFile:          tokenFile,
		TokenCreateRole:    "testrole",
		Policies:           []string{"foo-server"},
		MaxRenewalInterval: 1 * time.Hour,
	}

	marhsaledYAML := `token_file:
  path: /test/token
  mode: 0600
creation_role: testrole
policies:
  - foo-server
max_renew: 1h
required_policies:
  - test-issuer
`
	return cert, marhsaledYAML
}

func TestVaultTokenUnmarshalYAML(t *testing.T) {
	expected, testText := getTestVaultTokenInfo()
	dst := &VaultToken{}

	err := yaml.Unmarshal([]byte(testText), dst)
	if err != nil {
		t.Fatalf("Unable to unmarshal: %v", err)
	}
	dst.TokenFile.populateUserGroupData()

	if diff := deep.Equal(dst, expected); diff != nil {
		t.Errorf("Unmarshaled not equal to expected:")
		for _, d := range diff {
			t.Error(d)
		}
		t.FailNow()
	}

}
