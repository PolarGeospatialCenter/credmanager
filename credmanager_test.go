package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.umn.edu/pgc-devops/credmanager-api/types"
	"github.umn.edu/pgc-devops/credmanager-api/vaultstate"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
)

func getTestCredmanagerHandler(ctx context.Context) (*CredmanagerHandler, error) {
	consulConfig := RunConsul(ctx)
	vaultConfig := RunVault(ctx)
	consulClient, err := consul.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}
	store, err := inventory.NewSampleInventoryStore()
	if err != nil {
		return nil, err
	}
	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}
	vaultClient.SetToken(vaultTestRootToken)

	err = loadVaultPolicyData(vaultClient)
	if err != nil {
		return nil, fmt.Errorf("unable to setup vault policies: %v", err)
	}

	secret, err := vaultClient.Auth().Token().CreateOrphan(&vault.TokenCreateRequest{Policies: []string{"issuer"}})
	if err != nil {
		return nil, fmt.Errorf("Unable to create issuer token: %v", err)
	}

	vaultClient.SetToken(secret.Auth.ClientToken)

	return NewCredmanagerHandler(store, consulClient, NewTokenManager(vaultClient), vaultstate.NewVaultStateManager("nodes/bootable", vaultClient)), nil
}

func TestValidNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := getTestCredmanagerHandler(ctx)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	nodes, err := h.store.Nodes()
	if err != nil {
		t.Fatalf("Unable to get nodes from sample inventory: %v", err)
	}

	// This node doesn't exist, so should fail.
	if h.requestFromValidNode(&types.TokenRequest{Hostname: "bad-node"}, net.ParseIP("127.0.0.1")) {
		t.Fatalf("Request from invalid node accepted.")
	}

	// The IP address of the node in the sample inventory is not 127.0.0.1, so this should fail
	if h.requestFromValidNode(&types.TokenRequest{Hostname: nodes["sample0001"].Hostname}, net.ParseIP("127.0.0.1")) {
		t.Fatalf("Request from invalid node accepted.")
	}

	if !h.requestFromValidNode(&types.TokenRequest{Hostname: nodes["sample0000"].Hostname}, net.ParseIP("127.0.0.1")) {
		t.Fatalf("Request from valid node rejected.")
	}
}

func TestCredmanagerNodeEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := getTestCredmanagerHandler(ctx)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	vaultClient := h.tokenManager.vault
	_ = vaultClient
	nodes, _ := h.store.Nodes()

	//both sample nodes should fail at first
	for _, node := range nodes {
		if h.nodeEnabled(node) {
			t.Errorf("Check for whether node is enabled returned true instead of false: %s", node.ID())
		}
		// Activate node
		myToken := vaultClient.Token()
		vaultClient.SetToken(vaultTestRootToken)
		err := h.nodeState.Activate(node.ID(), time.Second)
		if err != nil {
			t.Errorf("Unable to activate node: %v", err)
		}
		vaultClient.SetToken(myToken)
	}

	time.Sleep(5 * time.Millisecond)
	for _, node := range nodes {
		if !h.nodeEnabled(node) {
			t.Errorf("Check for whether node is enabled returned false instead of true: %s", node.ID())
		}
	}

	time.Sleep(time.Second)

	for _, node := range nodes {
		if h.nodeEnabled(node) {
			t.Errorf("Check for whether node is enabled returned true instead of false: %s", node.ID())
		}
	}

}

func TestCredmanagerHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := getTestCredmanagerHandler(ctx)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	nodes, err := h.store.Nodes()
	if err != nil {
		t.Fatalf("Unable to get nodes from sample inventory: %v", err)
	}

	vaultClient := h.tokenManager.vault
	for _, node := range nodes {
		myToken := vaultClient.Token()
		vaultClient.SetToken(vaultTestRootToken)
		err := h.nodeState.Activate(node.ID(), time.Second)
		if err != nil {
			t.Errorf("Unable to activate node: %v", err)
		}
		vaultClient.SetToken(myToken)
	}

	body, err := json.Marshal(&types.TokenRequest{Hostname: nodes["sample0001"].Hostname, Policies: []string{"bar-worker-ssh-cert"}})
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

	tokendata := &types.TokenResponse{}
	err = json.Unmarshal(bodytext, tokendata)
	if err != nil {
		t.Fatalf("Unable to unmarshal token response: %v", err)
	}
}

func TestCredmanagerHandlerBadPolicyRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := getTestCredmanagerHandler(ctx)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	nodes, err := h.store.Nodes()
	if err != nil {
		t.Fatalf("Unable to get nodes from sample inventory: %v", err)
	}

	vaultClient := h.tokenManager.vault
	for _, node := range nodes {
		myToken := vaultClient.Token()
		vaultClient.SetToken(vaultTestRootToken)
		err := h.nodeState.Activate(node.ID(), time.Second)
		if err != nil {
			t.Errorf("Unable to activate node: %v", err)
		}
		vaultClient.SetToken(myToken)
	}

	body, err := json.Marshal(&types.TokenRequest{Hostname: nodes["sample0001"].Hostname, Policies: []string{"bar-worker-ssh-cert", "disallowed-policy"}})
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
	if response.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("Request didn't return a 400 as expected %d: %s", response.Result().StatusCode, string(bodytext))
	}
}
