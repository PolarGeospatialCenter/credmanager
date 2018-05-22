package vaulthelper

import (
	"net/http"
	"testing"

	vault "github.com/hashicorp/vault/api"
	gock "gopkg.in/h2non/gock.v1"
)

func TestVaultAuthSuccess(t *testing.T) {
	httpClient := http.DefaultClient

	gock.InterceptClient(httpClient)
	gock.DisableNetworking()
	defer gock.EnableNetworking()
	defer gock.Off() // Flush pending mocks after test execution
	//http://169.254.169.254/latest/dynamic/instance-identity/pkcs7
	gock.New("http://169.254.169.254").
		Get("/latest/dynamic/instance-identity/pkcs7").
		Reply(200).BodyString(`MIICiTCCAfICCQD6m7oRw0uXOjANBgkqhkiG9w0BAQUFADCBiDELMAkGA1UEBhMC
VVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZBbWF6
b24xFDASBgNVBAsTC0lBTSBDb25zb2xlMRIwEAYDVQQDEwlUZXN0Q2lsYWMxHzAd
BgkqhkiG9w0BCQEWEG5vb25lQGFtYXpvbi5jb20wHhcNMTEwNDI1MjA0NTIxWhcN
MTIwNDI0MjA0NTIxWjCBiDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYD
VQQHEwdTZWF0dGxlMQ8wDQYDVQQKEwZBbWF6b24xFDASBgNVBAsTC0lBTSBDb25z
b2xlMRIwEAYDVQQDEwlUZXN0Q2lsYWMxHzAdBgkqhkiG9w0BCQEWEG5vb25lQGFt
YXpvbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMaK0dn+a4GmWIWJ
21uUSfwfEvySWtC2XADZ4nB+BLYgVIk60CpiwsZ3G93vUEIO3IyNoH/f0wYK8m9T
rDHudUZg3qX4waLG5M43q7Wgc/MbQITxOUSQv7c7ugFFDzQGBzZswY6786m86gpE
Ibb3OhjZnzcvQAaRHhdlQWIMm2nrAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAtCu4
nUhVVxYUntneD9+h8Mg9q6q+auNKyExzyLwaxlAoo7TJHidbtS4J5iNmZgXL0Fkb
FFBjvSfpJIlJ00zbhNYS5f6GuoEDmFJl0ZxBHjJnyp378OD8uTs7fLvjx79LjSTb
NYiytVbZPQUQ5Yaxu2jXnimvw3rrszlaEXAMPLE`)

	gock.New("http://127.0.0.1:8100").Post("/v1/auth/aws/login").Reply(200).BodyString(`{
	  "auth": {
	    "renewable": true,
	    "lease_duration": 1800000,
	    "metadata": {
	      "role_tag_max_ttl": "0",
	      "instance_id": "i-de0f1344",
	      "ami_id": "ami-fce36983",
	      "role": "dev-role",
	      "auth_type": "ec2"
	    },
	    "policies": [
	      "default",
	      "dev"
	    ],
	    "accessor": "20b89871-e6f2-1160-fb29-31c2f6d4645e",
	    "client_token": "c9368254-3f21-aded-8a6f-7c818e81b17a"
	  }
	}`)

	client, _ := vault.NewClient(&vault.Config{Address: "http://127.0.0.1:8100", HttpClient: httpClient})
	secret, err := LoginWithEC2InstanceProfile(client, "role", "nonce")
	if err != nil {
		t.Errorf("Error logging in with instance profile: %v", err)
	}

	if secret == nil || secret.Auth == nil {
		t.Errorf("Login returned nil token")
	}

	if secret != nil && secret.Auth != nil && secret.Auth.ClientToken != "c9368254-3f21-aded-8a6f-7c818e81b17a" {
		t.Errorf("Wrong token returned: %s", secret.Auth.ClientToken)
	}
}
