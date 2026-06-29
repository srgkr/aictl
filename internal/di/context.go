package di

import (
	configClear "github.com/POSIdev-community/aictl/internal/core/usecase/config/clear"
	"github.com/POSIdev-community/aictl/internal/core/usecase/config/set"
	"github.com/POSIdev-community/aictl/internal/core/usecase/config/show"
	"github.com/POSIdev-community/aictl/internal/core/usecase/config/unset"
	"github.com/POSIdev-community/aictl/internal/presenter/context"
)

func buildContextCmd(a *adapters) (*context.CmdContext, error) {
	clearUC, err := configClear.NewUseCase(a.config, a.cli)
	if err != nil {
		return nil, err
	}
	cmdClear := context.NewConfigClearCommand(clearUC)

	setUC, err := set.NewUseCase(a.config, a.cfg)
	if err != nil {
		return nil, err
	}
	cmdSet := context.NewConfigSetCommand(a.cfg, setUC)

	showUC, err := show.NewUseCase(a.config, a.cli, a.cfg)
	if err != nil {
		return nil, err
	}
	cmdShow := context.NewConfigShowCommand(showUC)

	unsetUC, err := unset.NewUseCase(a.config, a.cfg)
	if err != nil {
		return nil, err
	}
	cmdUnset := context.NewConfigUnsetCommand(unsetUC)

	return context.NewContextCmd(cmdClear, cmdSet, cmdShow, cmdUnset), nil
}
