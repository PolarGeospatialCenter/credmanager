package main

import (
	"errors"
	"fmt"
	"regexp"

	vault "github.com/hashicorp/vault/api"
	credmanagertypes "github.umn.edu/pgc-devops/credmanager-api/types"
	inventorytypes "github.umn.edu/pgc-devops/inventory-ingest/inventory/types"
)

var (
	roleNameRegexp    = `[\w-]+`
	ErrPolicyMismatch = errors.New("requested policies don't match the policies that are available for the node")
)

// TokenManager Handles the issuing of tokens
type TokenManager struct {
	vault *vault.Client
}

// NewTokenManager returns a new token manager
func NewTokenManager(vault *vault.Client) *TokenManager {
	m := &TokenManager{}
	m.vault = vault
	endpointRegexp, _ := regexp.Compile(`^auth/token/create/` + roleNameRegexp + `$`)
	m.vault.SetWrappingLookupFunc(func(op, path string) string {
		if op == "POST" && endpointRegexp.MatchString(path) {
			return "5m"
		}
		return ""
	})
	return m
}

func (m *TokenManager) lookupTokenRole(roleName string) (map[string]interface{}, error) {
	valid, err := regexp.MatchString("^"+roleNameRegexp+"$", roleName)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, fmt.Errorf("bad role name: %s", roleName)
	}

	request := m.vault.NewRequest("GET", fmt.Sprintf("/v1/auth/token/roles/%s", roleName))
	response, err := m.vault.RawRequest(request)
	if err != nil {
		return nil, response.Error()
	}

	defer response.Body.Close()
	out := make(map[string]interface{})
	err = response.DecodeJSON(&out)
	if err != nil {
		return nil, fmt.Errorf("unable to decode response from vault server: %v", err)
	}
	roleData, ok := out["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid data returned from vault for role: %s", roleName)
	}
	return roleData, nil
}

func (m *TokenManager) getNodeTokenRole(node *inventorytypes.InventoryNode) (string, error) {
	if node.Role != "" && node.System.ID() != "" {
		return fmt.Sprintf("credmanager-%s-%s", node.System.ID(), node.Role), nil
	}
	return "", fmt.Errorf("unable to build a valid rolename for %s", node.ID())
}

func (m *TokenManager) GetAllowedPolicies(node *inventorytypes.InventoryNode) ([]string, error) {
	roleName, err := m.getNodeTokenRole(node)
	if err != nil {
		return nil, fmt.Errorf("Unable to lookup token role corresponding to %s: %v", node.ID(), err)
	}

	roleData, err := m.lookupTokenRole(roleName)
	if err != nil {
		return nil, fmt.Errorf("unable to lookup role information for role: %s", roleName)
	}

	allowedPoliciesRaw, ok := roleData["allowed_policies"].([]interface{})
	if !ok {
		return []string{}, nil
	}

	allowedPolicies := make([]string, len(allowedPoliciesRaw))
	for i := range allowedPoliciesRaw {
		policy, ok := allowedPoliciesRaw[i].(string)
		if !ok {
			return nil, fmt.Errorf("unable to convert supplied %v to string", allowedPoliciesRaw[i])
		}
		allowedPolicies[i] = policy
	}

	return allowedPolicies, nil
}

// CreateNodeToken returns a token for a given node
func (m *TokenManager) CreateNodeToken(node *inventorytypes.InventoryNode, policies []string) (string, error) {
	roleName, err := m.getNodeTokenRole(node)
	if err != nil {
		return "", fmt.Errorf("unable to get token role for %s: %v", node.ID(), err)
	}

	allowed, err := m.GetAllowedPolicies(node)
	if err != nil {
		return "", fmt.Errorf("unable to lookup policies for %s: %v", node.ID(), err)
	}

	allowedSet := credmanagertypes.NewPolicySet(allowed...)
	requestedSet := credmanagertypes.NewPolicySet(policies...)
	if !requestedSet.IsSubsetOf(allowedSet) {
		return "", ErrPolicyMismatch
	}

	tokenRequest := vault.TokenCreateRequest{Policies: policies}
	secret, err := m.vault.Auth().Token().CreateWithRole(&tokenRequest, roleName)
	if err != nil {
		return "", err
	}
	if secret.WrapInfo == nil {
		return "", fmt.Errorf("no wrapped token issued, probably a bug related to the wrapped token creation endpoint")
	}
	return secret.WrapInfo.Token, nil
}
