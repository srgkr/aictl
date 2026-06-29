package di

import (
	"github.com/POSIdev-community/aictl/internal/core/usecase/update/sources"
	"github.com/POSIdev-community/aictl/internal/core/usecase/update/sources/git"
	"github.com/POSIdev-community/aictl/internal/presenter/update"
)

func buildUpdateCmd(a *adapters) (*update.CmdUpdate, error) {
	sourcesUC, err := sources.NewUseCase(a.ai, a.cli, a.cfg)
	if err != nil {
		return nil, err
	}

	gitUC, err := git.NewUseCase(a.ai, a.cli)
	if err != nil {
		return nil, err
	}
	cmdGit := update.NewUpdateSourcesGitCmd(gitUC)

	cmdSources := update.NewUpdateSourcesCmd(a.cfg, sourcesUC, cmdGit)

	return update.NewUpdateCmd(a.cfg, cmdSources), nil
}
