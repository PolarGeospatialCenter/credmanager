package client

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	credmanagertypes "github.com/PolarGeospatialCenter/credmanager/pkg/types"
	vaulttest "github.com/PolarGeospatialCenter/dockertest/pkg/vault"
	vault "github.com/hashicorp/vault/api"
)

func TestValidToken(t *testing.T) {
	valid := "30171EE0-62F9-423F-B287-EAEFCFD9A2FF"
	invalid := []string{
		"vli43va47gvbwb347LFU3V7R4LBGR",
		"as30171EE0-62F9-423F-B287-EAEFCFD9A2FFd",
		"fd30171EE0-62F9-423F-B287-EAEFCFD9A2FF",
		"30171EE0-62F9-423FB287-EAEFCFD9A2FF",
		"30171EE0-62F9-423Z-B287-EAEFCFD9A2FF",
	}
	if !ValidTokenFormat(valid) {
		t.Errorf("Valid token failed validation")
	}

	for _, invalidToken := range invalid {
		if ValidTokenFormat(invalidToken) {
			t.Errorf("Invalid token didn't fail as expected: %s", invalidToken)
		}
	}
}

type fakeHTTPClient struct {
	Status   int
	Response interface{}
}

func (f *fakeHTTPClient) Do(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	switch f.Status {
	case http.StatusCreated:
		w.WriteHeader(f.Status)
		w.Header().Set("Content-type", "application/json")
		body, err := json.Marshal(f.Response)
		if err != nil {
			return nil, err
		}
		w.Write(body)
	case 0:
		w.WriteHeader(http.StatusInternalServerError)
	default:
		w.WriteHeader(f.Status)
	}
	return w.Result(), nil
}

func TestRequestSecret(t *testing.T) {
	cm := &CredManagerClient{}
	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusCreated, Response: &credmanagertypes.Response{SecretID: "221ECFD7-E093-45EF-8070-E1FA284A06C0"}})

	request := &credmanagertypes.Request{ClientID: "sample-0-0"}
	token, err := cm.requestSecret(request)
	if err != nil {
		t.Errorf("Request failed: %v", err)
	}

	if token != "221ECFD7-E093-45EF-8070-E1FA284A06C0" {
		t.Errorf("Wrong token returned: %s", token)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusCreated, Response: &credmanagertypes.Response{SecretID: "221ECFD7sdfs"}})
	_, err = cm.requestSecret(request)
	if err != ErrBadResponse {
		t.Errorf("Bad token accepted as valid or other error: %v", err)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusInternalServerError})
	_, err = cm.requestSecret(request)
	if err != ErrServerError {
		t.Errorf("Request didn't return a server error as expected, actual error: %v", err)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusBadGateway})
	_, err = cm.requestSecret(request)
	if err.Error() != "server returned an unexpected error: 502 Bad Gateway" {
		t.Errorf("Wrong error returned for unhandled responses: %v", err)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusForbidden})
	_, err = cm.requestSecret(request)
	if err != ErrTokenRequestDenied {
		t.Errorf("Request didn't return token request denied error as expected, actual err: %v", err)
	}
}

func TestLoadNonExistTokenFile(t *testing.T) {
	cm := &CredManagerClient{TokenFile: "/tmp/badfile-221ECFD7-E093-45EF-8070-E1FA284A06C0"}
	_, err := cm.loadToken()
	if err != errNoTokenFile {
		t.Fatalf("Temporary token file exists, or it's non-existence isn't being detected properly: %v", err)
	}
}

func TestSaveAndLoadToken(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "testtoken")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(tempFile.Name())

	sampleToken := "221ECFD7-E093-45EF-8070-E1FA284A06C0"

	cm := &CredManagerClient{TokenFile: tempFile.Name()}

	_, err = cm.loadToken()
	if err != ErrInvalidTokenFormat {
		t.Fatalf("Empty temporary token file isn't recognized as an invalid token format error: %v", err)
	}

	err = cm.saveToken(sampleToken)
	if err != nil {
		t.Fatalf("Failed to save sample token: %v", err)
	}

	loadedToken, err := cm.loadToken()
	if err != nil {
		t.Errorf("Unable to load saved token: %v", err)
	}
	if loadedToken != sampleToken {
		t.Errorf("Token loaded from file doesn't match the one saved: loaded '%s', saved '%s'", loadedToken, sampleToken)
	}
}

func TestGetToken(t *testing.T) {

	ctx := context.Background()
	vaultInstance, err := vaulttest.Run(ctx)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	rootToken := vaultInstance.RootToken()
	vaultClient, err := vault.NewClient(vaultInstance.Config())

	vaultClient.SetToken(rootToken)

	_, err = vaultClient.Logical().Write("sys/auth/approle", map[string]interface{}{"type": "approle"})
	if err != nil {
		t.Fatalf("unable to enable approle backend: %v", err)
	}

	testAppRole := map[string]interface{}{
		"policies":           []string{},
		"explicit_max_ttl":   0,
		"name":               "credmanager-sample0001",
		"orphan":             false,
		"period":             1,
		"secret_id_num_uses": 1,
		"secret_id_ttl":      "60s",
		"renewable":          true,
	}

	_, err = vaultClient.Logical().Write("auth/approle/role/credmanager-sample0001", testAppRole)
	if err != nil {
		t.Fatalf("Unable to create approle: %v", err)
	}

	roleID := map[string]interface{}{"role_id": "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"}
	_, err = vaultClient.Logical().Write("auth/approle/role/credmanager-sample0001/role-id", roleID)
	if err != nil {
		t.Fatalf("Unable to set role_id on app role: %v", err)
	}

	tempDir, err := ioutil.TempDir("", "getToken")
	if err != nil {
		t.Fatalf("Unable to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cm := &CredManagerClient{ClientID: "sample0001", TokenFile: filepath.Join(tempDir, "token"), RoleIDFile: filepath.Join(tempDir, "roleid")}

	err = ioutil.WriteFile(cm.RoleIDFile, []byte("ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"), 0600)
	if err != nil {
		t.Fatalf("Unable to write test role id to file: %v", err)
	}

	secret, err := vaultClient.Logical().Write("auth/approle/role/credmanager-sample0001/secret-id", nil)
	if err != nil {
		t.Fatalf("Unable to get test secret from vault: %v", err)
	}

	// our fake api server should return a valid token to simulate a wrapping token
	fakeAPIServer := &fakeHTTPClient{Status: http.StatusCreated, Response: &credmanagertypes.Response{SecretID: secret.Data["secret_id"].(string)}}
	cm.SetHTTPClient(fakeAPIServer)
	token, err := cm.GetToken(vaultClient)
	if err != nil {
		t.Fatalf("An error ocurred while getting the token: %v", err)
	}

	if !ValidTokenFormat(token) {
		t.Errorf("GetToken returned an invalid token string: %s", token)
	}

	fakeAPIServer = &fakeHTTPClient{Status: http.StatusBadRequest, Response: &credmanagertypes.CredmanagerErrorResponse{Message: "Shouldn't need to access service for second GetToken"}}
	cm.SetHTTPClient(fakeAPIServer)
	readToken, err := cm.GetToken(vaultClient)
	if err != nil {
		t.Fatalf("An error ocurred while getting the token from file: %v", err)
	}

	if token != readToken {
		t.Errorf("GetToken returned an incorrect token while re-reading from file: expected '%s', got '%s'", token, readToken)
	}

}
