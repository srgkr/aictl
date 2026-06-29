package clear

import (
	"context"

	"github.com/POSIdev-community/aictl/internal/core/domain/validation"
)

type CFG interface {
	ClearCurrentContext() error
}

type CLI interface {
	ShowText(ctx context.Context, text string)
	AskConfirmation(ctx context.Context, question string) (bool, error)
}

type UseCase struct {
	configAdapter CFG
	cliAdapter    CLI
}

func NewUseCase(configAdapter CFG, cliAdapter CLI) (*UseCase, error) {
	if configAdapter == nil {
		return nil, validation.NewRequiredError("configAdapter")
	}

	if cliAdapter == nil {
		return nil, validation.NewRequiredError("cliAdapter")
	}

	return &UseCase{configAdapter, cliAdapter}, nil
}

func (u *UseCase) Execute(ctx context.Context, skipConfirm bool) error {
	var (
		ok  = skipConfirm
		err error
	)

	if !ok {
		ok, err = u.cliAdapter.AskConfirmation(ctx,
			"Are you sure you want to delete the existing configuration?")
		if err != nil {
			return err
		}
	}

	if !ok {
		u.cliAdapter.ShowText(ctx, "Cancelled")

		return nil
	}

	if err := u.configAdapter.ClearCurrentContext(); err != nil {
		return err
	}

	return nil
}
