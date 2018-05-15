package main

import (
	"fmt"

	vault "github.com/hashicorp/vault/api"
)

var (
	issuerPolicy = `path "auth/approle/role/credmanager-sample0001/secret-id" {
  capabilities = ["update"]
}

path "secret/data/nodes/bootable/*" {
	capabilities = ["read", "delete"]
}
`
	// Role used to issue tokens.  Setting the period to 1 forces the ttl to 1s for the tokens.
	testAppRole = map[string]interface{}{
		"policies":           "bar-worker-ssh-cert",
		"explicit_max_ttl":   0,
		"name":               "credmanager-sample0001",
		"orphan":             false,
		"period":             1,
		"secret_id_num_uses": 1,
		"secret_id_ttl":      "60s",
		"renewable":          true,
	}

	testClientPolicy = `path "secret/bar-worker-cert" {
	capabilities = ["read"]
}`
)

func loadVaultPolicyData(vaultClient *vault.Client) error {
	_, err := vaultClient.Logical().Write("sys/auth/approle", map[string]interface{}{"type": "approle"})
	if err != nil {
		return fmt.Errorf("unable to enable approle backend: %v", err)
	}

	err = vaultClient.Sys().PutPolicy("issuer", issuerPolicy)
	if err != nil {
		return fmt.Errorf("Unable to create issuer policy: %v", err)
	}

	_, err = vaultClient.Logical().Write("auth/approle/role/credmanager-sample0001", testAppRole)
	if err != nil {
		return fmt.Errorf("unable to create test app role: %v", err)
	}
	err = vaultClient.Sys().PutPolicy("bar-worker-ssh-cert", testClientPolicy)
	if err != nil {
		return fmt.Errorf("Unable to create test client policy: %v", err)
	}

	return nil
}
