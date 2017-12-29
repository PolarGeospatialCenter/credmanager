package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	consul "github.com/hashicorp/consul/api"
	"github.umn.edu/pgc-devops/credmanager-api/types"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
	inventorytypes "github.umn.edu/pgc-devops/inventory-ingest/inventory/types"
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

func (response *CredmanagerResponse) SendToken(token string) error {
	data, err := json.Marshal(&types.TokenResponse{Token: token})
	if err != nil {
		return err
	}
	response.WriteHeader(http.StatusCreated)
	response.Header().Set("Content-Type", "application/json")
	response.Write(data)
	return nil
}

// CredmanagerHandler implements http.Handler
type CredmanagerHandler struct {
	store        inventory.InventoryStore
	consul       *consul.Client
	tokenManager *TokenManager
}

func NewCredmanagerHandler(store inventory.InventoryStore, consul *consul.Client, tm *TokenManager) *CredmanagerHandler {
	m := &CredmanagerHandler{}
	m.store = store
	m.consul = consul
	m.tokenManager = tm
	return m
}

func (m *CredmanagerHandler) getNode(tr *types.TokenRequest) (*inventorytypes.InventoryNode, error) {
	inv, err := inventory.NewInventory(m.store)
	if err != nil {
		log.Printf("Unable to create inventory: %v", err)
		return nil, err
	}
	return inv.GetNodeByHostname(tr.Hostname)
}

// RequestFromValidNode returns true if and only if r 'from' a node in the InventoryStore
func (m *CredmanagerHandler) requestFromValidNode(tr *types.TokenRequest) bool {
	_, err := m.getNode(tr)
	return err == nil
}

func (m *CredmanagerHandler) nodeRegisteredInConsul(tr *types.TokenRequest) bool {
	node, err := m.getNode(tr)
	if err != nil {
		return false
	}
	consulNode, _, err := m.consul.Catalog().Node(node.Hostname, &consul.QueryOptions{})
	if err != nil {
		return false
	}
	return consulNode != nil
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
		return
	}

	// Is the request from a known host?
	if !m.requestFromValidNode(request) {
		response.JsonMessage(http.StatusForbidden, "Request not allowed")
		return
	}

	if m.nodeRegisteredInConsul(request) {
		response.JsonMessage(http.StatusForbidden, "Request not allowed")
		return
	}

	node, err := m.getNode(request)
	if err != nil {
		log.Printf("Unable to get node: %v", err)
		response.JsonMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}

	token, err := m.tokenManager.CreateNodeToken(node)
	if err != nil {
		log.Printf("Unable to create token: %v", err)
		response.JsonMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}

	err = response.SendToken(token)
	if err != nil {
		log.Printf("Unable to send token response: %v", err)
		response.JsonMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}
}
