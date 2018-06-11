package credentials

import (
	"fmt"

	ctemplatecfg "github.com/hashicorp/consul-template/config"
	ctemplatemgr "github.com/hashicorp/consul-template/manager"
	vault "github.com/hashicorp/vault/api"
)

type CredentialTemplateRenewer struct {
	renewCh chan *RenewOutput
	doneCh  chan error
}

func newCredentialTemplateRenewer(runner *ctemplatemgr.Runner, source *CredentialTemplate, action PostRenewAction) *CredentialTemplateRenewer {
	r := &CredentialTemplateRenewer{}
	r.renewCh = make(chan *RenewOutput)
	r.doneCh = make(chan error)

	go func() {
		for _ = range runner.RenderEventCh() {
			for _, e := range runner.RenderEvents() {
				if e.DidRender {
					r.renewCh <- &RenewOutput{Source: source, Message: "render completed", RenewalTime: e.LastDidRender}
					if action != nil {
						action.Do()
					}
				}
			}
		}
	}()

	go func() {
		for err := range runner.ErrCh {
			r.doneCh <- err
		}
	}()

	return r
}

func (r *CredentialTemplateRenewer) RenewCh() <-chan *RenewOutput {
	return r.renewCh
}

func (r *CredentialTemplateRenewer) DoneCh() <-chan error {
	return r.doneCh
}

// CredentialTemplate wraps an invocation of consul-template, using the vault
// token and address configured for the vaultClient
type CredentialTemplate struct {
	TemplateFile string          `yaml:"template_file"`
	OutputFile   *CredentialFile `yaml:"output_file"`
	Notifies     string          `yaml:"notifies"`
	vaultClient  *vault.Client
	renewer      *CredentialTemplateRenewer
	runner       *ctemplatemgr.Runner
}

func (t *CredentialTemplate) Manage(vaultClient *vault.Client) error {
	t.vaultClient = vaultClient
	cfg := ctemplatecfg.DefaultConfig()
	vaultAddress := vaultClient.Address()
	vaultToken := vaultClient.Token()
	myFalse := false
	myTrue := true
	myVault := &ctemplatecfg.VaultConfig{
		Address:    &vaultAddress,
		Token:      &vaultToken,
		RenewToken: &myFalse,
	}
	cfg.Vault = cfg.Vault.Merge(myVault)
	templateConfig := ctemplatecfg.DefaultTemplateConfig()
	outputPath := t.OutputFile.Path()
	templateConfig.Destination = &outputPath
	templateConfig.Source = &t.TemplateFile
	templateConfig.CreateDestDirs = &myTrue

	cfg.Templates = &ctemplatecfg.TemplateConfigs{templateConfig}

	runner, err := ctemplatemgr.NewRunner(cfg, false, false)
	if err != nil {
		return fmt.Errorf("error creating consult-template runner: %v", err)
	}
	t.runner = runner

	go t.runner.Start()
	var action PostRenewAction
	if t.Notifies != "" {
		action = &ReloadOrRestartSystemdUnit{UnitName: t.Notifies}
	}
	t.renewer = newCredentialTemplateRenewer(t.runner, t, action)

	return nil
}

func (t *CredentialTemplate) Stop() {
	t.runner.Stop()
}

func (t *CredentialTemplate) Renewer() Renewer {
	return t.renewer
}

func (t *CredentialTemplate) String() string {
	return fmt.Sprintf("Template for: %s", t.OutputFile.Path())
}
