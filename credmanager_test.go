package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.umn.edu/pgc-devops/credmanager-api/types"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
)

func getTestCredmanagerHandler(ctx context.Context, cluster bool) (*CredmanagerHandler, error) {
	var consulConfig *consul.Config
	if cluster {
		consulConfig = RunConsulCluster(ctx)
	} else {
		consulConfig = RunConsul(ctx)
	}
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
	return NewCredmanagerHandler(store, consulClient, NewTokenManager(vaultClient)), nil
}

func TestValidNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := getTestCredmanagerHandler(ctx, false)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	if !h.requestFromValidNode(&types.TokenRequest{Hostname: "bar-ab01-02"}) {
		t.Fatalf("Request from valid node rejected.")
	}
}

func TestNodeRegisteredInConsul(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := getTestCredmanagerHandler(ctx, true)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	if !h.nodeRegisteredInConsul(&types.TokenRequest{Hostname: "bar-ab00-02"}) {
		t.Errorf("Registered node returned false")
	}

	if h.nodeRegisteredInConsul(&types.TokenRequest{Hostname: "bar-ab01-02"}) {
		t.Errorf("Unregistered node returned true")
	}
}

func TestCredmanagerHandler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, err := getTestCredmanagerHandler(ctx, true)
	if err != nil {
		t.Fatalf("Error creating test handler: %v", err)
	}

	body, err := json.Marshal(&types.TokenRequest{Hostname: "bar-ab01-02"})
	if err != nil {
		t.Fatalf("Unable to marshal request body: %v", err)
	}
	request, err := http.NewRequest("POST", "http://localhost:8080/token", bytes.NewBuffer(body))
	if err != nil {
		t.Fatalf("Unable to create token request: %v", err)
	}
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
