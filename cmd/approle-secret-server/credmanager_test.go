package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PolarGeospatialCenter/credmanager/pkg/types"
	"github.com/PolarGeospatialCenter/credmanager/pkg/vaulthelper"
	"github.com/PolarGeospatialCenter/credmanager/pkg/vaultstate"
	vaulttest "github.com/PolarGeospatialCenter/dockertest/pkg/vault"
	vault "github.com/hashicorp/vault/api"
)

func getTestCredmanagerHandler(instance *vaulttest.Instance) (*CredmanagerHandler, string, error) {
	vaultClient, err := vault.NewClient(instance.Config())
	if err != nil {
		return nil, "", err
	}
	vaultClient.SetToken(instance.RootToken())

	err = loadVaultPolicyData(vaultClient)
	if err != nil {
		return nil, "", fmt.Errorf("unable to setup vault policies: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"issuer"}})
	if err != nil {
		return nil, "", fmt.Errorf("Unable to create issuer token: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	return NewCredmanagerHandler(NewAppRoleSecretManager(vaultClient), vaultstate.NewVaultStateManager("nodes/bootable", vaulthelper.NewKV(vaultClient, "secret", 2))), instance.RootToken(), nil
}

func TestCredmanagerNodeEnabled(t *testing.T) {
	ctx := context.Background()
	vaultInstance, err := vaulttest.Run(ctx)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	defer vaultInstance.Stop(ctx)

	h, vaultTestRootToken, err := getTestCredmanagerHandler(vaultInstance)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	vaultClient := h.secretManager.vaultClient
	nodes := []string{"good-node-1"}

	//both sample nodes should fail at first
	for _, node := range nodes {
		if h.nodeEnabled(node) {
			t.Errorf("Check for whether node is enabled returned true instead of false: %s", node)
		}
		// Activate node
		myToken := vaultClient.Token()
		vaultClient.SetToken(vaultTestRootToken)
		err := h.nodeState.Activate(node, time.Second)
		if err != nil {
			t.Errorf("Unable to activate node: %v", err)
		}
		vaultClient.SetToken(myToken)
	}

	time.Sleep(5 * time.Millisecond)
	for _, node := range nodes {
		if !h.nodeEnabled(node) {
			t.Errorf("Check for whether node is enabled returned false instead of true: %s", node)
		}
	}

	time.Sleep(time.Second)

	for _, node := range nodes {
		if h.nodeEnabled(node) {
			t.Errorf("Check for whether node is enabled returned true instead of false: %s", node)
		}
	}

}

func TestCredmanagerHandler(t *testing.T) {
	ctx := context.Background()
	vaultInstance, err := vaulttest.Run(ctx)
	if err != nil {
		t.Fatalf("Unable to create vault client: %v", err)
	}
	defer vaultInstance.Stop(ctx)

	h, vaultTestRootToken, err := getTestCredmanagerHandler(vaultInstance)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	nodes := []string{"sample0001"}

	vaultClient := h.secretManager.vaultClient
	for _, node := range nodes {
		myToken := vaultClient.Token()
		vaultClient.SetToken(vaultTestRootToken)
		err := h.nodeState.Activate(node, time.Second)
		if err != nil {
			t.Errorf("Unable to activate node: %v", err)
		}
		vaultClient.SetToken(myToken)
	}

	body, err := json.Marshal(&types.Request{ClientID: "sample0001"})
	if err != nil {
		t.Fatalf("Unable to marshal request body: %v", err)
	}
	request, err := http.NewRequest("POST", "http://localhost:8080/token", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Unable to create token request: %v", err)
	}
	request.RemoteAddr = "10.0.0.1:65534"

	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	bodytext, _ := ioutil.ReadAll(response.Result().Body)
	if response.Result().StatusCode != http.StatusCreated {
		t.Fatalf("Request failed %d: %s", response.Result().StatusCode, string(bodytext))
	}

	tokendata := &types.Response{}
	err = json.Unmarshal(bodytext, tokendata)
	if err != nil {
		t.Fatalf("Unable to unmarshal token response: %v", err)
	}
}
