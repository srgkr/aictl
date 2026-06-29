package di

import (
	"github.com/POSIdev-community/aictl/internal/core/usecase/delete/projects"
	deletePresenter "github.com/POSIdev-community/aictl/internal/presenter/delete"
)

func buildDeleteCmd(a *adapters) (*deletePresenter.CmdDelete, error) {
	projectsUC, err := projects.NewUseCase(a.ai, a.cli)
	if err != nil {
		return nil, err
	}
	cmdProjects := deletePresenter.NewDeleteProjectsCommand(projectsUC)

	return deletePresenter.NewDeleteCmd(a.cfg, cmdProjects), nil
}
