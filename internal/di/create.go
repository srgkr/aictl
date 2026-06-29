package di

import (
	"github.com/POSIdev-community/aictl/internal/core/usecase/create/branch"
	"github.com/POSIdev-community/aictl/internal/core/usecase/create/project"
	"github.com/POSIdev-community/aictl/internal/presenter/create"
)

func buildCreateCmd(a *adapters) (*create.CmdCreate, error) {
	branchUC, err := branch.NewUseCase(a.ai, a.cli)
	if err != nil {
		return nil, err
	}
	cmdBranch := create.NewCreateBranchCmd(a.cfg, branchUC)

	projectUC, err := project.NewUseCase(a.ai, a.cli)
	if err != nil {
		return nil, err
	}
	cmdProject := create.NewCreateProjectCmd(projectUC)

	return create.NewCreateCmd(a.cfg, cmdBranch, cmdProject), nil
}
