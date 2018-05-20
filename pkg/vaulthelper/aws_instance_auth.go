package vaulthelper

import (
	"fmt"
	"io/ioutil"
	"net/http"

	vault "github.com/hashicorp/vault/api"
)

func GetEC2InstanceIdentityPKCS7() (string, error) {
	resp, err := http.Get("http://169.254.169.254/latest/dynamic/instance-identity/pkcs7")
	if err != nil {
		return "", fmt.Errorf("unable to request instance-identity PKCS7 signature: %v", err)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read response body: %v", err)
	}
	return string(data), nil
}

func LoginWithEC2InstanceProfile(client *vault.Client, role string, nonce string) (*vault.Secret, error) {
	pkcs7, err := GetEC2InstanceIdentityPKCS7()
	if err != nil {
		return nil, fmt.Errorf("unable to get pkcs7 identity signature: %v", err)
	}
	authData := map[string]interface{}{
		"pkcs7": pkcs7,
		"role":  role,
		"nonce": nonce,
	}

	return client.Logical().Write("/auth/aws/login", authData)
}
