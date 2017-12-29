package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
)

var serviceRandomSrc = rand.New(rand.NewSource(time.Now().UnixNano()))

const vaultTestRootToken = "701432d1-00e7-7c94-10c4-8450ab3c4b31"

func RunConsul(ctx context.Context) *consul.Config {
	port := serviceRandomSrc.Int() % 10000
	go func() {
		portConfig := fmt.Sprintf("ports { http = %d https = -1 dns = -1 serf_lan = %d serf_wan = %d server = %d}", 8500+port, 8301+port, 8302+port, 8300+port)
		cmd := exec.CommandContext(ctx, "consul", "agent", "-dev", "-bind", "127.0.0.1", "-hcl", portConfig, "-node", "testserver")
		cmd.Run()
	}()
	config := consul.DefaultConfig()
	config.Address = fmt.Sprintf("localhost:%d", 8500+port)
	return config
}

func RunConsulCluster(ctx context.Context) *consul.Config {
	port := serviceRandomSrc.Int() % 10000
	port2 := port + 10
	dataPath, err := ioutil.TempDir("", "consultest")
	if err != nil {
		log.Fatal(err)
	}
	serverDataPath := filepath.Join(dataPath, "server")
	clientDataPath := filepath.Join(dataPath, "client")
	go func() {
		select {
		case <-ctx.Done():
			os.RemoveAll(dataPath)
		}
	}()
	go func() {
		portConfig := fmt.Sprintf("ports { http = %d https = -1 dns = -1 serf_lan = %d serf_wan = %d server = %d}", 8500+port, 8301+port, 8302+port, 8300+port)
		cmd := exec.CommandContext(ctx, "consul", "agent", "-server", "-bind", "127.0.0.1", "-bootstrap-expect", "1", "-hcl", portConfig, "-data-dir", serverDataPath, "-node", "testserver")
		// cmd.Stdout = os.Stdout
		// cmd.Stderr = os.Stderr
		cmd.Run()
	}()
	go func() {
		portConfig := fmt.Sprintf("ports { http = %d https = -1 dns = -1 serf_lan = %d}", 8500+port2, 8300+port2)
		cmd := exec.CommandContext(ctx, "consul", "agent", "-retry-interval", "100ms", "-retry-join", fmt.Sprintf("127.0.0.1:%d", port+8301), "-hcl", portConfig, "-node", "bar-ab00-02", "-data-dir", clientDataPath)
		// cmd.Stdout = os.Stdout
		// cmd.Stderr = os.Stderr
		cmd.Run()
	}()
	config := consul.DefaultConfig()
	config.Address = fmt.Sprintf("localhost:%d", 8500+port)

	client, err := consul.NewClient(config)
	if err != nil {
		log.Fatalf("Unable to create client")
	}

	var count = 0
	for count < 10 {
		n, _, _ := client.Catalog().Nodes(&consul.QueryOptions{})
		if len(n) == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
		count += 1
	}

	return config
}

func RunVault(ctx context.Context) *vault.Config {
	port := serviceRandomSrc.Int() % 10000
	listenAddress := fmt.Sprintf("127.0.0.1:%d", 8200+port)
	go func() {
		cmd := exec.CommandContext(ctx, "vault", "server", "-dev", "-dev-root-token-id", vaultTestRootToken, "-dev-listen-address", listenAddress)
		cmd.Run()
	}()
	config := vault.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", listenAddress)
	time.Sleep(100 * time.Millisecond)
	return config
}

func TestConsulCluster(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	consulConfig := RunConsulCluster(ctx)
	client, err := consul.NewClient(consulConfig)
	if err != nil {
		t.Fatalf("Unable to create client")
	}

	n, _, err := client.Catalog().Nodes(&consul.QueryOptions{})
	if len(n) != 2 {
		t.Fatalf("Consul cluster creation failed.")
	}
}
