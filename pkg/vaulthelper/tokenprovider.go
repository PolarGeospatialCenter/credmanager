package vaulthelper

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"

	vault "github.com/hashicorp/vault/api"
)

var (
	ErrTokenNotFound = errors.New("no token found")
)

type TokenProvider interface {
	RetrieveToken() (string, error)
}

// TokenExpiredFunc returns true if the token is valid
type TokenValidFunc func(token string) bool

func NewDefaultChainProvider(client *vault.Client) *TokenChainProvider {
	provider := &TokenChainProvider{
		Providers: []TokenProvider{
			&EnvTokenProvider{},
			&LoginTokenProvider{},
			&TlsCertTokenProvider{Client: client},
		},
		Validator: func(token string) bool {
			localClient, err := client.Clone()
			if err != nil {
				return false
			}
			localClient.SetToken(token)
			_, err = localClient.Auth().Token().LookupSelf()
			if err != nil {
				return false
			}
			return true
		},
	}
	return provider
}

type TokenChainProvider struct {
	Providers []TokenProvider
	Validator TokenValidFunc
}

func (p *TokenChainProvider) RetrieveToken() (string, error) {
	for _, provider := range p.Providers {
		token, err := provider.RetrieveToken()
		if err == ErrTokenNotFound {
			continue
		} else if err != nil {
			return "", fmt.Errorf("unknown error getting token: %v", err)
		}

		if p.Validator(token) {
			return token, nil
		}
	}
	return "", ErrTokenNotFound
}

type EnvTokenProvider struct{}

func (p *EnvTokenProvider) RetrieveToken() (string, error) {
	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return "", ErrTokenNotFound
	}
	return token, nil
}

// LoginTokenProvider finds tokens output by `vault login`
type LoginTokenProvider struct{}

func (p *LoginTokenProvider) RetrieveToken() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("unable to get current user: %v", err)
	}

	token, err := ioutil.ReadFile(path.Join(u.HomeDir, ".vault-token"))
	if err != nil {
		return "", ErrTokenNotFound
	}
	return string(token), nil
}

type TlsCertTokenProvider struct {
	Client *vault.Client
}

func (p *TlsCertTokenProvider) RetrieveToken() (string, error) {
	secret, err := p.Client.Logical().Write("auth/cert/login", map[string]interface{}{})
	if err != nil {
		return "", ErrTokenNotFound
	}

	tokenId, err := secret.TokenID()
	if err != nil {
		return "", ErrTokenNotFound
	}

	return tokenId, nil
}
