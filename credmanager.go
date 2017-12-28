package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
	"github.umn.edu/pgc-devops/credmanager-api/types"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
)

// CredmanagerResponse wraps a ResponseWriter, providing useful responses
type CredmanagerResponse struct {
	http.ResponseWriter
}

func (response *CredmanagerResponse) JsonMessage(status int, msg string) {
	response.WriteHeader(status)
	response.Header().Set("Content-Type", "application/json")
	data := &struct {
		Msg string
	}{
		Msg: msg,
	}
	body, err := json.Marshal(data)
	if err != nil {
		return
	}
	response.Write(body)
}

// CredmanagerHandler implements http.Handler
type CredmanagerHandler struct {
	Store  inventory.InventoryStore
	Consul *consul.Client
	Vault  *vault.Client
}

// RequestFromValidNode returns true if and only if r 'from' a node in the InventoryStore
func (m *CredmanagerHandler) requestFromValidNode(tr *types.TokenRequest) bool {
	inv, err := inventory.NewInventory(m.Store)
	if err != nil {
		log.Printf("Unable to create inventory: %v", err)
		return false
	}
	_, err = inv.GetNodeByHostname(tr.Hostname)
	if err == nil {
		return true
	}
	return false
}

func (m *CredmanagerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response := &CredmanagerResponse{w}
	request := &types.TokenRequest{}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		response.JsonMessage(http.StatusInternalServerError, "An error ocurred")
	}

	err = json.Unmarshal(body, request)
	if err != nil {
		response.JsonMessage(http.StatusBadRequest, "Request not formatted properly")
	}
	// Is the request from a known host?
	if !m.requestFromValidNode(request) {
		response.JsonMessage(http.StatusUnauthorized, "Request not allowed")
	}
}
