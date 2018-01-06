package client

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	vault "github.com/hashicorp/vault/api"
	credmanagertypes "github.umn.edu/pgc-devops/credmanager-api/types"
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
	Status        int
	TokenResponse *credmanagertypes.TokenResponse
}

func (f *fakeHTTPClient) Do(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	switch f.Status {
	case http.StatusCreated:
		w.WriteHeader(f.Status)
		w.Header().Set("Content-type", "application/json")
		body, err := json.Marshal(f.TokenResponse)
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

func TestRequestToken(t *testing.T) {
	cm := &CredManagerClient{Hostname: "sample-0-0"}
	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusCreated, TokenResponse: &credmanagertypes.TokenResponse{Token: "221ECFD7-E093-45EF-8070-E1FA284A06C0"}})

	token, err := cm.requestToken()
	if err != nil {
		t.Errorf("Request failed: %v", err)
	}

	if token != "221ECFD7-E093-45EF-8070-E1FA284A06C0" {
		t.Errorf("Wrong token returned: %s", token)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusCreated, TokenResponse: &credmanagertypes.TokenResponse{Token: "221ECFD7sdfs"}})
	_, err = cm.requestToken()
	if err != ErrBadResponse {
		t.Errorf("Bad token accepted as valid or other error: %v", err)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusInternalServerError})
	_, err = cm.requestToken()
	if err != ErrServerError {
		t.Errorf("Request didn't return a server error as expected, actual error: %v", err)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusBadGateway})
	_, err = cm.requestToken()
	if err.Error() != "server returned an unexpected error: 502 Bad Gateway" {
		t.Errorf("Wrong error returned for unhandled responses: %v", err)
	}

	cm.SetHTTPClient(&fakeHTTPClient{Status: http.StatusForbidden})
	_, err = cm.requestToken()
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

type testUnwrapper struct {
	WrappedToken string
}

func (f *testUnwrapper) Unwrap(string) (*vault.Secret, error) {
	return &vault.Secret{Auth: &vault.SecretAuth{ClientToken: f.WrappedToken}}, nil
}

func TestGetToken(t *testing.T) {
	tempFile, err := ioutil.TempFile("", "testtoken")
	if err != nil {
		log.Fatal(err)
	}
	// Remove tempfile because we just need the name
	os.Remove(tempFile.Name())
	// Defer a second remove since we're expecting it to be created by the client
	defer os.Remove(tempFile.Name())

	cm := &CredManagerClient{TokenFile: tempFile.Name(), Hostname: "sample-0-0"}

	// our fake api server should return a valid token to simulate a wrapping token
	fakeAPIServer := &fakeHTTPClient{Status: http.StatusCreated, TokenResponse: &credmanagertypes.TokenResponse{Token: "221ECFD7-E093-45EF-8070-E1FA284A06C0"}}
	realToken := "A89B3399-1A16-42EB-BE83-4CCDF9166884"
	cm.SetHTTPClient(fakeAPIServer)
	cm.SetTokenUnwrapper(&testUnwrapper{WrappedToken: realToken})
	token, err := cm.GetToken()
	if err != nil {
		t.Fatalf("An error ocurred while getting the token: %v", err)
	}

	if token != realToken {
		t.Errorf("GetToken returned an incorrect token: expected '%s', got '%s'", realToken, token)
	}

	// tempfile should exist now, reloading
	badToken := "BADB3399-1A16-42EB-BE83-4CCDF9166884"
	cm.SetHTTPClient(fakeAPIServer)
	cm.SetTokenUnwrapper(&testUnwrapper{WrappedToken: badToken})
	token, err = cm.GetToken()
	if err != nil {
		t.Fatalf("An error ocurred while getting the token from file: %v", err)
	}

	if token != realToken {
		t.Errorf("GetToken returned an incorrect token while re-reading from file: expected '%s', got '%s'", realToken, token)
	}

}
