package vaultstate

import (
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type stateRecord struct {
	TTL            time.Duration
	CreatedTime    time.Time
	ExpirationTime time.Time
}

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

// Deactivate removes a key from the vault tree, thus deactivating it
func (vsm *VaultStateManager) Deactivate(key string) error {
	_, err := vsm.vaultClient.Logical().Delete(vsm.keyPath(key))
	return err
}

func (vsm *VaultStateManager) getRecord(key string) *stateRecord {
	secret, err := vsm.vaultClient.Logical().Read(vsm.keyPath(key))
	if err != nil || secret == nil {
		return nil
	}
	createdTime := time.Time{}
	err = createdTime.UnmarshalText([]byte(secret.Data["created"].(string)))
	if err != nil {
		return nil
	}
	ttl := time.Duration(secret.LeaseDuration) * time.Second
	expiration := createdTime.Add(ttl)
	return &stateRecord{CreatedTime: createdTime, ExpirationTime: expiration, TTL: ttl}
}

// Active returns true if the key exists and the ttl has not expired, false otherwise
func (vsm *VaultStateManager) Active(key string) bool {
	record := vsm.getRecord(key)
	if record == nil {
		return false
	}
	created := record.CreatedTime.UnixNano()
	expiration := record.ExpirationTime.UnixNano()
	now := time.Now().UnixNano()

	return record.TTL.Seconds() > 0 && created <= now && now < expiration
}

func (vsm *VaultStateManager) Status(key string) string {
	record := vsm.getRecord(key)
	if record == nil {
		return fmt.Sprintf("record for %s not found", key)
	}
	return fmt.Sprintf("%s: TTL %s, Created at %s, Expires at %s", key, record.TTL, record.CreatedTime, record.ExpirationTime)
}
