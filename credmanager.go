package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"

	"github.umn.edu/pgc-devops/credmanager-api/types"
	credmanagertypes "github.umn.edu/pgc-devops/credmanager-api/types"
	"github.umn.edu/pgc-devops/credmanager-api/vaultstate"
	"github.umn.edu/pgc-devops/inventory-ingest/inventory"
	inventorytypes "github.umn.edu/pgc-devops/inventory-ingest/inventory/types"
)

// CredmanagerResponse wraps a ResponseWriter, providing useful responses
type CredmanagerResponse struct {
	http.ResponseWriter
}

// JSONMessage writes a json response with the specified StatusCode and message
func (response *CredmanagerResponse) JSONMessage(status int, msg string) {
	response.WriteHeader(status)
	response.Header().Set("Content-Type", "application/json")
	data := &credmanagertypes.CredmanagerErrorResponse{Message: msg}
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
	store         inventory.InventoryStore
	secretManager *AppRoleSecretManager
	nodeState     *vaultstate.VaultStateManager
}

// NewCredmanagerHandler builds a new CredmanagerHandler
func NewCredmanagerHandler(store inventory.InventoryStore, sm *AppRoleSecretManager, vaultState *vaultstate.VaultStateManager) *CredmanagerHandler {
	m := &CredmanagerHandler{}
	m.store = store
	m.secretManager = sm
	m.nodeState = vaultState
	return m
}

func (m *CredmanagerHandler) getNode(tr *types.Request) (*inventorytypes.InventoryNode, error) {
	inv, err := inventory.NewInventory(m.store)
	if err != nil {
		log.Printf("Unable to create inventory: %v", err)
		return nil, err
	}
	return inv.GetNode(tr.ClientID)
}

// RequestFromValidNode returns true if and only if r 'from' a node in the InventoryStore
func (m *CredmanagerHandler) requestFromValidNode(tr *types.Request, src net.IP) bool {
	if tr == nil || src == nil {
		log.Printf("Unable to verify node, missing either request or source IP")
		return false
	}

	node, err := m.getNode(tr)
	if err != nil {
		log.Printf("No matching node found for request: %v, error was: %v", tr, err)
		nodes, err := m.store.Nodes()
		if err == nil {
			nodelist := make([]string, len(nodes))
			i := 0
			for _, node := range nodes {
				nodelist[i] = node.Hostname
				i++
			}
			log.Printf("Nodes found: %v", nodelist)
		} else {
			log.Printf("Unable to lookup any nodes: %v", err)
		}
		return false
	}

	for _, ip := range node.IPs() {
		if src.String() == ip.String() {
			return true
		}
	}
	log.Printf("Unable to find %s in list of node IPs %v", src, node.IPs())

	return false
}

func (m *CredmanagerHandler) nodeEnabled(node *inventorytypes.InventoryNode) bool {
	return m.nodeState.Active(node.ID())
}

func (m *CredmanagerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response := &CredmanagerResponse{w}
	request := &types.Request{}
	if r.Method != "POST" {
		response.JSONMessage(http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Printf("Unable to split request RemoteAddr address:port string : %v", err)
		response.JSONMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}
	srcIP := net.ParseIP(host)

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		response.JSONMessage(http.StatusInternalServerError, "An error ocurred")
	}

	err = json.Unmarshal(body, request)
	if err != nil {
		response.JSONMessage(http.StatusBadRequest, "Request not formatted properly")
		return
	}

	// Is the request from a known host?
	if !m.requestFromValidNode(request, srcIP) {
		log.Printf("Request from invalid node or wrong source (%s): %v", srcIP, request)
		response.JSONMessage(http.StatusForbidden, "Request not allowed: invalid source")
		return
	}

	node, err := m.getNode(request)
	if err != nil {
		log.Printf("Unable to get node: %v", err)
		response.JSONMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}

	if !m.nodeEnabled(node) {
		log.Printf("Node not marked as bootable, denying request. %v", request)
		response.JSONMessage(http.StatusForbidden, "Request not allowed")
		return
	}

	secret, err := m.secretManager.GetSecret(node)
	if err != nil {
		log.Printf("Unable to create token: %v", err)
		response.JSONMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}

	err = m.nodeState.Deactivate(node.ID())
	if err != nil {
		log.Printf("WARNING: Unable to deactivate node %s: %v", node.ID(), err)
	}

	err = response.SendSecret(secret)
	if err != nil {
		log.Printf("Unable to send token response: %v", err)
		response.JSONMessage(http.StatusInternalServerError, "Request could not be handled")
		return
	}
}
