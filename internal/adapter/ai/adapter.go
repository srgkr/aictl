package ai

import (
	"context"
	"fmt"
	"io"

	"github.com/POSIdev-community/aictl/internal/core/domain/branch"
	"github.com/POSIdev-community/aictl/internal/core/domain/config"
	"github.com/POSIdev-community/aictl/internal/core/domain/project"
	"github.com/POSIdev-community/aictl/internal/core/domain/report"
	"github.com/POSIdev-community/aictl/internal/core/domain/scan"
	"github.com/POSIdev-community/aictl/internal/core/domain/scanstage"
	"github.com/POSIdev-community/aictl/internal/core/domain/settings"
	"github.com/POSIdev-community/aictl/internal/core/domain/statistic"
	"github.com/POSIdev-community/aictl/internal/core/domain/version"
	"github.com/POSIdev-community/aictl/pkg/clientai"
	clientai5x "github.com/POSIdev-community/aictl/pkg/clientai/5_x"
	"github.com/google/uuid"
)

type ClientAi interface {
}

type Adapter struct {
	client5x   *clientai5x.ClientAI
	baseClient *clientai.BaseClient

	cfg           *config.Config
	serverVersion version.Version
}

func NewAdapter(cfg *config.Config) (*Adapter, error) {
	base := clientai.NewBaseClient()
	client5x := clientai5x.NewAiClient(base)

	return &Adapter{client5x: client5x, baseClient: base, cfg: cfg}, nil
}

func (a *Adapter) Initialize(ctx context.Context) error {
	err := a.client5x.Initialize(ctx, a.cfg)
	if err != nil {
		return fmt.Errorf("initialize ai client: %w", err)
	}

	a.serverVersion, err = a.client5x.GetVersion(ctx)
	if err != nil {
		return fmt.Errorf("get version: %w", err)
	}

	err = a.resolveClient()
	if err != nil {
		return fmt.Errorf("resolve client: %w", err)
	}

	err = a.client5x.CheckLicense(ctx)
	if err != nil {
		return fmt.Errorf("check license: %w", err)
	}

	return nil
}

func (a *Adapter) InitializeWithRetry(ctx context.Context) error {
	err := a.Initialize(ctx)
	if err != nil {
		return fmt.Errorf("initialize ai adapter: %w", err)
	}

	a.client5x.AddJwtRetry()

	return nil
}

func (a *Adapter) resolveClient() error {
	minVersion, _ := version.NewVersion("5.0.0")
	maxVersion, _ := version.NewVersion("6.0.0")

	if a.serverVersion.Less(minVersion) {
		return fmt.Errorf("version less than 5.0.0")
	}

	if a.serverVersion.Greater(maxVersion) {
		return fmt.Errorf("version greater than 6.0.0")
	}

	// TODO: add initializing other client in future

	return nil
}

func (a *Adapter) GetDefaultSettings(ctx context.Context) (settings.ScanSettings, error) {
	return a.client5x.GetDefaultSettings(ctx)
}

func (a *Adapter) SetProjectSettings(ctx context.Context, projectId uuid.UUID, settings *settings.ScanSettings) error {
	return a.client5x.SetProjectSettings(ctx, projectId, settings)
}

func (a *Adapter) CreateBranch(ctx context.Context, projectId uuid.UUID, branchName, scanTargetPath string) (*uuid.UUID, error) {
	return a.client5x.CreateBranch(ctx, projectId, branchName, scanTargetPath)
}

func (a *Adapter) CreateProject(ctx context.Context, projectName string) (*uuid.UUID, error) {
	return a.client5x.CreateProject(ctx, projectName)
}

func (a *Adapter) DeleteProject(ctx context.Context, projectId uuid.UUID) error {
	return a.client5x.DeleteProject(ctx, projectId)
}

func (a *Adapter) ExistsProject(ctx context.Context, projectName string) (bool, error) {
	return a.client5x.ExistsProject(ctx, projectName)
}

func (a *Adapter) GetProjectId(ctx context.Context, projectName string) (*uuid.UUID, error) {
	return a.client5x.GetProjectId(ctx, projectName)
}

func (a *Adapter) GetProjects(ctx context.Context) ([]project.Project, error) {
	return a.client5x.GetProjects(ctx)
}

func (a *Adapter) GetProject(ctx context.Context, projectId uuid.UUID) (*project.Project, error) {
	return a.client5x.GetProject(ctx, projectId)
}

func (a *Adapter) GetDefaultTemplateId(ctx context.Context, reportType report.ReportType) (uuid.UUID, error) {
	return a.client5x.GetDefaultTemplateId(ctx, reportType)
}

func (a *Adapter) GetCustomTemplateId(ctx context.Context, reportName string) (uuid.UUID, error) {
	return a.client5x.GetCustomTemplateId(ctx, reportName)
}

func (a *Adapter) GetReport(ctx context.Context, projectId, scanResultId, templateId uuid.UUID, includeComments, includeDFD, includeGlossary bool, l10n string) (io.ReadCloser, error) {
	return a.client5x.GetReport(ctx, projectId, scanResultId, templateId, includeComments, includeDFD, includeGlossary, l10n)
}

func (a *Adapter) GetSbom(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	return a.client5x.GetSbom(ctx, projectId, scanResultId)
}

func (a *Adapter) GetScanLogs(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	return a.client5x.GetScanLogs(ctx, projectId, scanResultId)
}

func (a *Adapter) GetBranches(ctx context.Context, projectId uuid.UUID) ([]branch.Branch, error) {
	return a.client5x.GetBranches(ctx, projectId)
}

func (a *Adapter) GetLastScan(ctx context.Context, branchId uuid.UUID) (*scan.Scan, error) {
	return a.client5x.GetLastScan(ctx, branchId)
}

func (a *Adapter) GetScan(ctx context.Context, projectId, scanId uuid.UUID) (*scan.Scan, error) {
	return a.client5x.GetScan(ctx, projectId, scanId)
}

func (a *Adapter) GetScanAiproj(ctx context.Context, projectId, scanSettingsId uuid.UUID) (io.ReadCloser, error) {
	return a.client5x.GetScanAiproj(ctx, projectId, scanSettingsId)
}

func (a *Adapter) GetScanStage(ctx context.Context, projectId, scanId uuid.UUID) (scanstage.ScanStage, error) {
	return a.client5x.GetScanStage(ctx, projectId, scanId)
}

func (a *Adapter) GetScanQueue(ctx context.Context) ([]uuid.UUID, error) {
	return a.client5x.GetScanQueue(ctx)
}

func (a *Adapter) StartScanBranch(ctx context.Context, branchId uuid.UUID, scanLabel string) (uuid.UUID, error) {
	return a.client5x.StartScanBranch(ctx, branchId, scanLabel)
}

func (a *Adapter) StartScanProject(ctx context.Context, projectId uuid.UUID, scanLabel string) (uuid.UUID, error) {
	return a.client5x.StartScanProject(ctx, projectId, scanLabel)
}

func (a *Adapter) StopScan(ctx context.Context, scanResultId uuid.UUID) error {
	return a.client5x.StopScan(ctx, scanResultId)
}

func (a *Adapter) UpdateSources(ctx context.Context, projectId, branchId uuid.UUID, scanTargetPath string) error {
	return a.client5x.UpdateSources(ctx, projectId, branchId, scanTargetPath)
}

func (a *Adapter) GetVersion(ctx context.Context) (version.Version, error) {
	return a.serverVersion, nil
}
func (a *Adapter) GetHealthcheck(ctx context.Context) (bool, error) {
	return a.client5x.GetHealthcheck(ctx)
}
func (a *Adapter) CheckLicense(ctx context.Context) error {
	return a.client5x.CheckLicense(ctx)
}

func (a *Adapter) GetScanStatistic(ctx context.Context, projectId, scanResultId uuid.UUID) (*statistic.Statistic, error) {
	return a.client5x.GetScanStatistic(ctx, projectId, scanResultId)
}
