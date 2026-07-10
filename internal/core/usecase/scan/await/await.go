package await

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/POSIdev-community/aictl/internal/core/domain/config"
	"github.com/POSIdev-community/aictl/internal/core/domain/queue"
	"github.com/POSIdev-community/aictl/internal/core/domain/scanstage"
	"github.com/POSIdev-community/aictl/internal/core/domain/validation"
	"github.com/google/uuid"
)

const (
	Enqueued = "Enqueued"
	Aborted  = "Aborted"
	Done     = "Done"
	Failed   = "Failed"
)

type AI interface {
	InitializeWithRetry(ctx context.Context) error
	GetScanStage(ctx context.Context, projectId uuid.UUID, scanId uuid.UUID) (scanstage.ScanStage, error)
	GetScanItem(ctx context.Context, id uuid.UUID) (queue.Item, error)
}

type CLI interface {
	ShowText(ctx context.Context, text string)
	ShowTextf(ctx context.Context, format string, a ...any)
	ReturnText(ctx context.Context, text string)
}

type UseCase struct {
	aiAdapter  AI
	cliAdapter CLI
	cfg        *config.Config
}

func NewUseCase(aiAdapter AI, cliAdapter CLI, cfg *config.Config) (*UseCase, error) {
	if aiAdapter == nil {
		return nil, validation.NewRequiredError("aiAdapter")
	}

	if cliAdapter == nil {
		return nil, validation.NewRequiredError("cliAdapter")
	}

	return &UseCase{aiAdapter, cliAdapter, cfg}, nil
}

func (u *UseCase) Execute(ctx context.Context, scanId uuid.UUID) error {
	err := u.aiAdapter.InitializeWithRetry(ctx)
	if err != nil {
		return fmt.Errorf("initialize with retry: %w", err)
	}

	u.cliAdapter.ShowTextf(ctx, "awating scan, id '%v'", scanId.String())

	stage := scanstage.ScanStage{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		stage, err = u.aiAdapter.GetScanStage(ctx, u.cfg.ProjectId(), scanId)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}

			u.cliAdapter.ShowTextf(ctx, fmt.Sprintf("error getting scan stage: %v", err.Error()))

			time.Sleep(3 * time.Second)
			u.cliAdapter.ShowText(ctx, "...")
			continue
		}

		if scanComplete(stage) {
			break
		}

		if stage.Stage == Enqueued {
			item, queueErr := u.aiAdapter.GetScanItem(ctx, scanId)
			if queueErr != nil {
				if errors.Is(queueErr, context.Canceled) {
					return queueErr
				}

				u.cliAdapter.ShowTextf(ctx, "error getting scan queue: %v", queueErr.Error())
				time.Sleep(3 * time.Second)
				continue
			}

			if item.OutOf > 0 {
				u.cliAdapter.ShowTextf(ctx, "%s: %d/%d", strings.ToLower(stage.Stage), item.Place, item.OutOf)
			} else {
				u.cliAdapter.ShowTextf(ctx, "%s", strings.ToLower(stage.Stage))
			}
		} else {
			u.cliAdapter.ShowTextf(ctx, "%s: %d%%", strings.ToLower(stage.Stage), stage.Value)
		}

		time.Sleep(3 * time.Second)
	}

	u.cliAdapter.ShowTextf(ctx, "Scan '%s'", stage.Stage)
	u.cliAdapter.ReturnText(ctx, stage.Stage)

	return nil
}

func scanComplete(stage scanstage.ScanStage) bool {
	return stage.Stage == Done || stage.Stage == Failed || stage.Stage == Aborted
}
