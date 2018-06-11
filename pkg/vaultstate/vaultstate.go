package vaultstate

import (
	"fmt"
	"log"
	"time"

	"github.com/PolarGeospatialCenter/credmanager/pkg/vaulthelper"
)

type stateRecord struct {
	TTL              time.Duration
	SkipDeactivation bool
	CreatedTime      time.Time
}

func newRecord(ttl time.Duration) *stateRecord {
	r := &stateRecord{
		TTL:         ttl,
		CreatedTime: time.Now(),
	}
	return r
}

func (r *stateRecord) expirationTime() time.Time {
	return r.CreatedTime.Add(r.TTL)
}

func (r *stateRecord) Map() map[string]interface{} {
	data := make(map[string]interface{})
	data["ttl"] = r.TTL.String()
	created, _ := r.CreatedTime.MarshalText()
	data["created"] = string(created)
	data["skip_deactivation"] = r.SkipDeactivation
	return data
}

func (r *stateRecord) active(at time.Time) bool {
	created := r.CreatedTime.UnixNano()
	expiration := r.expirationTime().UnixNano()

	return r.TTL.Seconds() > 0 && created <= at.UnixNano() && at.UnixNano() < expiration
}

// VaultStateManager writes records to vault to indicate that an object is active
// for the duration of the ttl
type VaultStateManager struct {
	BasePath    string
	vaultClient *vaulthelper.KV
}

// NewVaultStateManager creates a VaultStateManager
func NewVaultStateManager(basePath string, kvClient *vaulthelper.KV) *VaultStateManager {
	vsm := &VaultStateManager{}
	vsm.BasePath = basePath
	vsm.vaultClient = kvClient
	return vsm
}

func (vsm *VaultStateManager) keyPath(key string) string {
	return fmt.Sprintf("%s/%s", vsm.BasePath, key)
}

// Activate the key for ttl duration
func (vsm *VaultStateManager) Activate(key string, ttl time.Duration) error {
	record := newRecord(ttl)
	err := vsm.writeRecord(key, record)
	return err
}

// Deactivate removes a key from the vault tree, thus deactivating it
func (vsm *VaultStateManager) Deactivate(key string) error {
	if vsm.getRecord(key).SkipDeactivation {
		return nil
	}

	err := vsm.vaultClient.DeleteLatest(vsm.keyPath(key))
	return err
}

func (vsm *VaultStateManager) writeRecord(key string, record *stateRecord) error {
	return vsm.vaultClient.Write(vsm.keyPath(key), record.Map(), nil)
}

func (vsm *VaultStateManager) getRecord(key string) *stateRecord {
	record, _, err := vsm.vaultClient.ReadLatest(vsm.keyPath(key))
	if err != nil {
		return nil
	}
	createdTime := time.Time{}
	recordCreated, ok := record["created"].(string)
	if !ok {
		return nil
	}

	err = createdTime.UnmarshalText([]byte(recordCreated))
	if err != nil {
		return nil
	}
	ttl, err := time.ParseDuration(record["ttl"].(string))
	if err != nil {
		log.Printf("Unable to parse duration: %v", err)
		return nil
	}

	skipDeactivation, ok := record["skip_deactivation"].(bool)
	if !ok {
		skipDeactivation = false
	}
	return &stateRecord{CreatedTime: createdTime, SkipDeactivation: skipDeactivation, TTL: ttl}
}

// Active returns true if the key exists and the ttl has not expired, false otherwise
func (vsm *VaultStateManager) Active(key string) bool {
	record := vsm.getRecord(key)
	if record == nil {
		return false
	}
	return record.active(time.Now())
}

func (vsm *VaultStateManager) Status(key string) string {
	record := vsm.getRecord(key)
	if record == nil {
		return fmt.Sprintf("record for %s not found", key)
	}
	return fmt.Sprintf("%s: TTL %s, Created at %s, Expires at %s", key, record.TTL, record.CreatedTime, record.expirationTime())
}
