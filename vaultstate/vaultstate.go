package vaultstate

import (
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// VaultStateManager writes records to vault to indicate that an object is active
// for the duration of the ttl
type VaultStateManager struct {
	BasePath    string
	vaultClient *vault.Client
}

// NewVaultStateManager creates a VaultStateManager
func NewVaultStateManager(path string, client *vault.Client) *VaultStateManager {
	vsm := &VaultStateManager{}
	vsm.BasePath = path
	vsm.vaultClient = client
	return vsm
}

func (vsm *VaultStateManager) keyPath(key string) string {
	return fmt.Sprintf("secret/%s/%s", vsm.BasePath, key)
}

// Activate the key for ttl duration
func (vsm *VaultStateManager) Activate(key string, ttl time.Duration) error {
	data := make(map[string]interface{})
	data["ttl"] = ttl.String()
	created, _ := time.Now().MarshalText()
	data["created"] = string(created)
	_, err := vsm.vaultClient.Logical().Write(vsm.keyPath(key), data)
	return err
}

// Active returns true if the key exists and the ttl has not expired, false otherwise
func (vsm *VaultStateManager) Active(key string) bool {
	secret, err := vsm.vaultClient.Logical().Read(vsm.keyPath(key))
	if err != nil || secret == nil {
		return false
	}

	createdTime := &time.Time{}
	err = createdTime.UnmarshalText([]byte(secret.Data["created"].(string)))
	if err != nil {
		return false
	}
	created := createdTime.UnixNano()
	ttl := time.Duration(secret.LeaseDuration) * time.Second
	expiration := createdTime.Add(ttl).UnixNano()
	now := time.Now().UnixNano()

	return ttl.Seconds() > 0 && created <= now && now < expiration
}
