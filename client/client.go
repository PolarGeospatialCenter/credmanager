package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"

	vault "github.com/hashicorp/vault/api"
	credmanagertypes "github.umn.edu/pgc-devops/credmanager-api/types"
)

type ErrClientError struct {
	Err error
}

func (e ErrClientError) Error() string {
	return fmt.Sprintf("this error shouldn't occur, it's likely a bug in the client: %v", e.Err)
}

var (
	// ErrInvalidTokenFormat returned when the token format is invalid
	ErrInvalidTokenFormat = errors.New("Token format is invalid")
	// ErrServerError is returned when the server returns a 500 or something else that's not our fault
	ErrServerError = errors.New("credmanager api server returned an error that wasn't our fault")
	// ErrTokenRequestDenied is returned when the server denies our request for a token
	ErrTokenRequestDenied = errors.New("request for a token was denied")
	// ErrBadResponse
	ErrBadResponse = errors.New("unable to parse server response")
	// Internal Errors
	errNoTokenFile = errors.New("token file doesn't exist")
)

// HTTPClient Interface specifies the pieces of http.Client that we use and provides
// an interface for testing purposes
type HTTPClient interface {
	Do(r *http.Request) (*http.Response, error)
}

type TokenUnwrapper interface {
	Unwrap(string) (*vault.Secret, error)
}

// ValidTokenFormat validates the format of a vault token returns true if valid
func ValidTokenFormat(token string) bool {
	tokenRegexp, _ := regexp.Compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
	return tokenRegexp.MatchString(token)
}

// CredManagerClient retrieves a vault token from a credmanager api server and
// stores it locally so that it can be used as long as it remains valid.
type CredManagerClient struct {
	ServerUrl  string `mapstructure:"server_url"`
	TokenFile  string `mapstructure:"token_file"`
	unwrapper  TokenUnwrapper
	httpClient HTTPClient
}

// SetHTTPClient sets the http client to use
func (cm *CredManagerClient) SetHTTPClient(client HTTPClient) {
	cm.httpClient = client
}

func (cm *CredManagerClient) getHTTPClient() HTTPClient {
	if cm.httpClient == nil {
		cm.httpClient = &http.Client{}
	}
	return cm.httpClient
}

// SetTokenUnwrapper sets the token unwrapper to use.
// NOTE: github.com/hashicorp/vault/api.Logical is a valid unwrapper
func (cm *CredManagerClient) SetTokenUnwrapper(unwrapper TokenUnwrapper) {
	cm.unwrapper = unwrapper
}

func (cm *CredManagerClient) GetToken(tokenRequest *credmanagertypes.TokenRequest) (string, error) {
	// Do we have an unwrapped token stored already?
	if tokenString, err := cm.loadToken(); err == nil {
		return tokenString, nil
	}

	wrappingTokenString, err := cm.requestToken(tokenRequest)
	if err != nil {
		return "", err
	}

	if cm.unwrapper == nil {
		return "", fmt.Errorf("token unwrapper not set and need to unwrap token")
	}

	secret, err := cm.unwrapper.Unwrap(wrappingTokenString)
	if err != nil {
		log.Fatalf("Unable to unwrap token %s\n", err)
	}

	tokenString := secret.Auth.ClientToken
	if !ValidTokenFormat(tokenString) {
		return "", fmt.Errorf("invalid token returned from server")
	}

	return tokenString, cm.saveToken(tokenString)
}

func (cm *CredManagerClient) requestToken(tokenRequest *credmanagertypes.TokenRequest) (string, error) {
	body, err := json.Marshal(tokenRequest)
	if err != nil {
		return "", ErrClientError{fmt.Errorf("error marshaling request: %v", err)}
	}
	r, err := http.NewRequest("POST", cm.ServerUrl, bytes.NewBuffer(body))
	if err != nil {
		return "", ErrClientError{fmt.Errorf("error creating credmanager request: %v", err)}
	}
	response, err := cm.getHTTPClient().Do(r)
	if err != nil {
		return "", ErrClientError{fmt.Errorf("error making http request to credmanager server: %v", err)}
	}
	switch response.StatusCode {
	case http.StatusCreated:
		tokenResponse := &credmanagertypes.TokenResponse{}
		responseBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return "", ErrClientError{fmt.Errorf("error reading response body into string: %v", err)}
		}
		err = json.Unmarshal(responseBody, tokenResponse)
		if err != nil {
			return "", ErrBadResponse
		}

		if !ValidTokenFormat(tokenResponse.Token) {
			return "", ErrBadResponse
		}
		return tokenResponse.Token, nil
	case http.StatusForbidden:
		return "", ErrTokenRequestDenied
	case http.StatusBadRequest:
		return "", ErrClientError{fmt.Errorf("bad request")}
	case http.StatusInternalServerError:
		return "", ErrServerError
	default:
		return "", fmt.Errorf("server returned an unexpected error: %s", response.Status)
	}
}

func (cm *CredManagerClient) loadToken() (string, error) {
	filename := cm.TokenFile

	_, err := os.Stat(filename)
	if err != nil && os.IsNotExist(err) {
		return "", errNoTokenFile
	} else if err != nil {
		return "", err
	}

	token, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}

	tokenString := string(token)
	if !ValidTokenFormat(tokenString) {
		return "", ErrInvalidTokenFormat
	}

	return tokenString, nil
}

func (cm *CredManagerClient) saveToken(token string) error {
	return ioutil.WriteFile(cm.TokenFile, []byte(token), 0600)
}
