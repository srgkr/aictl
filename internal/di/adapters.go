package di

import (
	"github.com/POSIdev-community/aictl/internal/adapter/ai"
	"github.com/POSIdev-community/aictl/internal/adapter/cli"
	configAdapter "github.com/POSIdev-community/aictl/internal/adapter/config"
	"github.com/POSIdev-community/aictl/internal/core/domain/config"
)

type adapters struct {
	cfg    *config.Config
	config *configAdapter.Adapter
	cli    *cli.Adapter
	ai     *ai.Adapter
}

func newAdapters(cfg *config.Config) (*adapters, error) {
	aiAdapter, err := ai.NewAdapter(cfg)
	if err != nil {
		return nil, err
	}

	return &adapters{
		cfg:    cfg,
		config: configAdapter.NewContextAdapter(),
		cli:    cli.NewAdapter(),
		ai:     aiAdapter,
	}, nil
}
