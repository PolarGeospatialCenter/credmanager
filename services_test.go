package main

import (
	"context"
	"fmt"
	"math/rand"
	"os/exec"
	"time"

	consul "github.com/hashicorp/consul/api"
	vault "github.com/hashicorp/vault/api"
)

var serviceRandomSrc = rand.New(rand.NewSource(time.Now().UnixNano()))

func RunConsul(ctx context.Context) *consul.Config {
	port := serviceRandomSrc.Int() % 10000
	go func() {
		portConfig := fmt.Sprintf("ports { http = %d https = -1 dns = -1 serf_lan = %d serf_wan = %d server = %d}", 8500+port, 8301+port, 8302+port, 8300+port)
		cmd := exec.CommandContext(ctx, "consul", "agent", "-dev", "-hcl", portConfig)
		cmd.Run()
	}()
	config := consul.DefaultConfig()
	config.Address = fmt.Sprintf("localhost:%d", 8500+port)
	return config
}

func RunVault(ctx context.Context) *vault.Config {
	port := serviceRandomSrc.Int() % 10000
	listenAddress := fmt.Sprintf("127.0.0.1:%d}", 8200+port)
	go func() {
		rootToken := "701432d1-00e7-7c94-10c4-8450ab3c4b31"
		cmd := exec.CommandContext(ctx, "vault", "server", "-dev", "-dev-root-token-id", rootToken, "-dev-listen-address", listenAddress)
		cmd.Run()
	}()
	config := vault.DefaultConfig()
	config.Address = listenAddress
	return config
}
