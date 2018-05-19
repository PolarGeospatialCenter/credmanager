package vaulthelper

import (
	"fmt"
	"strconv"

	vault "github.com/hashicorp/vault/api"
)

// WriteOptions see options for create/updates to the KV api
type WriteOptions struct {
	CasVersion int64 `json:"cas"`
}

// KV is used for accessing kv data in vault.  Only v2 compatible
type KV struct {
	MountPoint string
	Client     *vault.Client
	version    int
}

// NewKV creates a KV object for the kv backend mounted at mountPath
func NewKV(client *vault.Client, mountPath string, version int) *KV {
	kv := &KV{MountPoint: mountPath, Client: client, version: version}
	return kv
}

// GetMountVersion determines the version of a mounted backend.  Requires read access to /sys/mounts
func GetMountVersion(client *vault.Client, mountPath string) (int, error) {
	mounts, err := client.Sys().ListMounts()
	if err != nil {
		return 0, fmt.Errorf("unable to list mounts: %v", err)
	}

	mountInfo, ok := mounts[fmt.Sprintf("%s/", mountPath)]
	if !ok {
		return 0, fmt.Errorf("%s is not a valid mount path", mountPath)
	}

	if version, ok := mountInfo.Options["version"]; ok {
		v, err := strconv.Atoi(version)
		if err != nil {
			return 0, fmt.Errorf("unable to parse version of mountpoint '%s': %v", version, err)
		}
		return v, nil
	}

	return 0, fmt.Errorf("unable to determine mount version: version not specified in mount options")
}

func (kv *KV) dataPath(key string) string {
	var fullPath string
	switch kv.version {
	case 1:
		fullPath = fmt.Sprintf("%s/%s", kv.MountPoint, key)
	default:
		fullPath = fmt.Sprintf("%s/data/%s", kv.MountPoint, key)
	}
	return fullPath
}

// ReadLatest reads the latest version of a given secret
func (kv *KV) ReadLatest(key string) (map[string]interface{}, map[string]interface{}, error) {
	secret, err := kv.Client.Logical().Read(kv.dataPath(key))
	if err != nil || secret == nil {
		return nil, nil, fmt.Errorf("error reading latest version of secret: %v", err)
	}

	var data, metadata map[string]interface{}

	switch kv.version {
	case 1:
		data = secret.Data
		metadata = make(map[string]interface{})
	default:
		var ok bool
		data, ok = secret.Data["data"].(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("error extracting data from latest version of secret")
		}

		metadata, ok = secret.Data["metadata"].(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("error extracting data from latest version of secret")
		}
	}

	return data, metadata, nil
}

// Write writes a new version of the secret
func (kv *KV) Write(key string, data map[string]interface{}, options *WriteOptions) error {
	var wrappedData map[string]interface{}
	switch kv.version {
	case 1:
		wrappedData = data
	default:
		wrappedData = map[string]interface{}{"data": data}
		if options != nil {
			wrappedData["options"] = map[string]interface{}{"cas": options.CasVersion}
		}

	}
	_, err := kv.Client.Logical().Write(kv.dataPath(key), wrappedData)
	if err != nil {
		return fmt.Errorf("error writing secret: %v", err)
	}
	return nil
}

// DeleteLatest deletes the latest version of a key
func (kv *KV) DeleteLatest(key string) error {
	_, err := kv.Client.Logical().Delete(kv.dataPath(key))
	return err
}
