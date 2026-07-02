package get

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

type CmdGetScanAgents struct {
	*cobra.Command
}

type UseCaseGetScanAgents interface {
	Execute(ctx context.Context, quite bool) error
}

func NewGetScanAgentsCmd(uc UseCaseGetScanAgents) CmdGetScanAgents {
	var quite bool

	cmd := &cobra.Command{
		Use:   "scan-agents",
		Short: "Get scan agents",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			if err := uc.Execute(ctx, quite); err != nil {
				cmd.SilenceUsage = true

				return fmt.Errorf("'get scan-agents' usecase call: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&quite, "quite", "q", false, "Get only ids")

	return CmdGetScanAgents{cmd}
}
