package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/PolarGeospatialCenter/credmanager/pkg/types"
	"github.com/PolarGeospatialCenter/credmanager/pkg/vaultstate"
)

// CredmanagerResponse wraps a ResponseWriter, providing useful responses
type CredmanagerResponse struct {
	http.ResponseWriter
}

// JSONMessage writes a json response with the specified StatusCode and message
func (response *CredmanagerResponse) JSONMessage(status int, msg string) {
	response.WriteHeader(status)
	response.Header().Set("Content-Type", "application/json")
	data := &types.CredmanagerErrorResponse{Message: msg}
	body, err := json.Marshal(data)
	if err != nil {
		return
	}
	response.Write(body)
}

// SendToken returns a TokenResponse to the client
func (response *CredmanagerResponse) SendSecret(secret string) error {
	data, err := json.Marshal(&types.Response{SecretID: secret})
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
	secretManager *AppRoleSecretManager
	nodeState     *vaultstate.VaultStateManager
}

// NewCredmanagerHandler builds a new CredmanagerHandler
func NewCredmanagerHandler(sm *AppRoleSecretManager, vaultState *vaultstate.VaultStateManager) *CredmanagerHandler {
	m := &CredmanagerHandler{}
	m.secretManager = sm
	m.nodeState = vaultState
	return m
}

func (m *CredmanagerHandler) nodeEnabled(id string) bool {
	return m.nodeState.Active(id)
}

func (m *CredmanagerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response := &CredmanagerResponse{w}
	request := &types.Request{}
	if r.Method != "POST" {
		response.JSONMessage(http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		response.JSONMessage(http.StatusInternalServerError, "An error ocurred")
	}

	err = json.Unmarshal(body, request)
	if err != nil {
		response.JSONMessage(http.StatusBadRequest, "Request not formatted properly")
		return
	}

	if !m.nodeEnabled(request.ClientID) {
		log.Printf("Node not marked as bootable. (%s) -- Denying request. %v", m.nodeState.Status(request.ClientID), request)
		response.JSONMessage(http.StatusForbidden, "Request not allowed")
		return
	}

	secret, err := m.secretManager.GetSecret(request.ClientID)
	if err != nil {
		log.Printf("Unable to create token: %v", err)
		response.JSONMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}

	err = m.nodeState.Deactivate(request.ClientID)
	if err != nil {
		log.Printf("WARNING: Unable to deactivate node %s: %v", request.ClientID, err)
	}

	err = response.SendSecret(secret)
	if err != nil {
		log.Printf("Unable to send token response: %v", err)
		response.JSONMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}
}
