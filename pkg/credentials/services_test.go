package credentials

import (
	"context"
	"fmt"
	"math/rand"
	"os/exec"
	"time"

	vault "github.com/hashicorp/vault/api"
)

var serviceRandomSrc = rand.New(rand.NewSource(time.Now().UnixNano()))

const vaultTestRootToken = "701432d1-00e7-7c94-10c4-8450ab3c4b31"

func RunVault(ctx context.Context) *vault.Config {
	port := serviceRandomSrc.Int() % 10000
	listenAddress := fmt.Sprintf("127.0.0.1:%d", 8200+port)
	go func() {
		cmd := exec.CommandContext(ctx, "vault", "server", "-dev", "-dev-root-token-id", vaultTestRootToken, "-dev-listen-address", listenAddress)
		cmd.Run()
	}()
	config := vault.DefaultConfig()
	config.Address = fmt.Sprintf("http://%s", listenAddress)
	time.Sleep(200 * time.Millisecond)
	return config
}
