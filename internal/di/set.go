package di

import (
	"github.com/POSIdev-community/aictl/internal/core/usecase/set/project/settings"
	setPresenter "github.com/POSIdev-community/aictl/internal/presenter/set"
)

func buildSetCmd(a *adapters) (*setPresenter.CmdSet, error) {
	settingsUC, err := settings.NewUseCase(a.ai, a.cli, a.cfg)
	if err != nil {
		return nil, err
	}

	persistentPreRunESetCmd := setPresenter.NewPersistentPreRunESetCmd(a.cfg)
	persistentPreRunESetProjectCmd := setPresenter.NewPersistentPreRunESetProjectCmd(a.cfg, persistentPreRunESetCmd)

	cmdSettings := setPresenter.NewSetProjectSettingsCmd(settingsUC)
	cmdProject := setPresenter.NewSetProjectCmd(persistentPreRunESetProjectCmd, cmdSettings)

	return setPresenter.NewSetCmd(persistentPreRunESetCmd, cmdProject), nil
}
