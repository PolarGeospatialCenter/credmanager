package credentials

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-test/deep"
	vault "github.com/hashicorp/vault/api"
	yaml "gopkg.in/yaml.v1"
)

func TestCredentialTemplate(t *testing.T) {
	// get tempDir
	tempDir, err := ioutil.TempDir("", "templatetest")
	if err != nil {
		t.Fatalf("Unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Write test template
	templateFile := filepath.Join(tempDir, "foo.tmpl.yml")
	templateString := `{{ with secret "secret/client-data/bar" }}{{ .Data.value }}{{ end }}`
	err = ioutil.WriteFile(templateFile, []byte(templateString), 0644)

	outFile, err := NewCredentialFile(filepath.Join(tempDir, "foo.yml"), 0600, "", "")
	if err != nil {
		t.Fatalf("Unable to create output CredentialFile: %v", err)
	}

	tmpl := &CredentialTemplate{
		TemplateFile: templateFile,
		OutputFile:   outFile,
	}

	ctx, cancel := context.WithCancel(context.Background())
	vaultConfig := RunVault(ctx)
	defer cancel()

	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	vaultClient.SetToken(vaultTestRootToken)

	err = vaultClient.Sys().PutPolicy("test-client-secrets", `path "secret/client-data/*" { capabilities = ["read"] }`)
	if err != nil {
		t.Fatalf("Unable to create policy allowing access to secrets: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"test-client-secrets"}})
	if err != nil {
		t.Fatalf("Unable to create token with correct policy: %v", err)
	}

	// run Manage
	err = tmpl.Manage(vaultClient)
	if err != nil {
		t.Fatalf("Unable to run Manage(): %v", err)
	}
	// verify template output matches expected

	cases := []string{"Hello Vault!", "updated!", "updated again!", "updated yet again!"}
	interval, _ := time.ParseDuration("2s")
	tmr := time.NewTimer(interval)
	for _, expectedOutput := range cases {
		// change secrets in vault
		vaultClient.SetToken(vaultTestRootToken)
		_, err = vaultClient.Logical().Write("secret/client-data/bar", map[string]interface{}{"value": expectedOutput, "ttl": interval.String()})
		if err != nil {
			t.Fatalf("Unable to write test secret data: %v", err)
		}
		tmr.Reset(interval)
		t.Logf("Value set at: %s", time.Now())

		vaultClient.SetToken(secret.Auth.ClientToken)

		select {
		case <-tmr.C:
			t.Errorf("Timer expired before rendering: %s", expectedOutput)
		case renewal := <-tmpl.Renewer().RenewCh():
			t.Logf("Got renewal event: %v", renewal.String())
			contents, err := outFile.Read()
			if err != nil {
				t.Errorf("Unable to read from output file: %v", err)
			}

			if contents != expectedOutput {
				t.Errorf("Rendered output file doesn't match expected value: actual: '%s', expected: '%s'", contents, expectedOutput)
			}
		case err := <-tmpl.Renewer().DoneCh():
			if err != nil {
				t.Errorf("Error rendering for %s: %v", expectedOutput, err)
			}

		}
	}

	tmpl.Stop()
}

func getTestCredentialTemplateInfo() (*CredentialTemplate, string) {
	outFile, _ := NewCredentialFile(filepath.Join("/test", "foo.yml"), 0600, "", "")

	tmpl := &CredentialTemplate{
		TemplateFile: "test_data/foo.tmpl.yml",
		OutputFile:   outFile,
		Notifies:     "foo.service",
	}

	marhsaledYAML := `template_file: test_data/foo.tmpl.yml
output_file:
  path: /test/foo.yml
  mode: 0600
notifies: foo.service
required_policies:
  - test-client-secrets
`
	return tmpl, marhsaledYAML
}

func TestCredentialTemplateUnmarshalYAML(t *testing.T) {
	expected, testText := getTestCredentialTemplateInfo()
	dst := &CredentialTemplate{}

	err := yaml.Unmarshal([]byte(testText), dst)
	if err != nil {
		t.Fatalf("Unable to unmarshal: %v", err)
	}
	dst.OutputFile.populateUserGroupData()

	if diff := deep.Equal(dst, expected); diff != nil {
		t.Errorf("Unmarshaled not equal to expected:")
		for _, d := range diff {
			t.Error(d)
		}
		t.FailNow()
	}

}
