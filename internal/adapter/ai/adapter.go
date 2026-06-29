package ai

import (
	"context"
	"fmt"
	"io"

	"github.com/POSIdev-community/aictl/internal/adapter/ai/client"
	"github.com/POSIdev-community/aictl/internal/core/domain/branch"
	"github.com/POSIdev-community/aictl/internal/core/domain/config"
	"github.com/POSIdev-community/aictl/internal/core/domain/project"
	"github.com/POSIdev-community/aictl/internal/core/domain/queue"
	"github.com/POSIdev-community/aictl/internal/core/domain/report"
	"github.com/POSIdev-community/aictl/internal/core/domain/scan"
	"github.com/POSIdev-community/aictl/internal/core/domain/scanstage"
	"github.com/POSIdev-community/aictl/internal/core/domain/scantype"
	"github.com/POSIdev-community/aictl/internal/core/domain/settings"
	"github.com/POSIdev-community/aictl/internal/core/domain/statistic"
	"github.com/POSIdev-community/aictl/internal/core/domain/version"
	"github.com/google/uuid"
)

type ClientAi interface {
	GetDefaultSettings(ctx context.Context) (settings.ScanSettings, error)
	SetProjectSettings(ctx context.Context, projectId uuid.UUID, settings *settings.ScanSettings) error
	CreateBranch(ctx context.Context, projectId uuid.UUID, branchName, scanTargetPath string) (*uuid.UUID, error)
	CreateProject(ctx context.Context, projectName string) (*uuid.UUID, error)
	DeleteProject(ctx context.Context, projectId uuid.UUID) error
	ExistsProject(ctx context.Context, projectName string) (bool, error)
	GetProjectId(ctx context.Context, projectName string) (*uuid.UUID, error)
	GetProjects(ctx context.Context) ([]project.Project, error)
	GetProject(ctx context.Context, projectId uuid.UUID) (*project.Project, error)
	GetDefaultTemplateId(ctx context.Context, reportType report.ReportType) (uuid.UUID, error)
	GetCustomTemplateId(ctx context.Context, reportName string) (uuid.UUID, error)
	GetReport(ctx context.Context, projectId, scanResultId, templateId uuid.UUID, includeComments, includeDFD, includeGlossary bool, l10n string) (io.ReadCloser, error)
	GetSbom(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error)
	GetScanLogs(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error)
	GetBranches(ctx context.Context, projectId uuid.UUID) ([]branch.Branch, error)
	GetScans(ctx context.Context, branchId uuid.UUID) ([]scan.Scan, error)
	GetLastScan(ctx context.Context, branchId uuid.UUID) (*scan.Scan, error)
	GetScan(ctx context.Context, projectId, scanId uuid.UUID) (*scan.Scan, error)
	GetScanAiproj(ctx context.Context, projectId, scanSettingsId uuid.UUID) (io.ReadCloser, error)
	GetScanStage(ctx context.Context, projectId, scanId uuid.UUID) (scanstage.ScanStage, error)
	GetScanItem(ctx context.Context, id uuid.UUID) (queue.Item, error)
	StartScanBranch(ctx context.Context, branchId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error)
	StartScanProject(ctx context.Context, projectId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error)
	StopScan(ctx context.Context, scanResultId uuid.UUID) error
	UpdateSources(ctx context.Context, projectId, branchId uuid.UUID, scanTargetPath string) error
	GetHealthcheck(ctx context.Context) (bool, error)
	CheckLicense(ctx context.Context) error
	GetScanStatistic(ctx context.Context, projectId, scanResultId uuid.UUID) (*statistic.Statistic, error)
}

type jwtRetrier interface {
	AddJwtRetry()
}

var (
	minSupportedVersion, _ = version.NewVersion("5.0.0")
	client6xMinVersion, _  = version.NewVersion("6.0.0")
	maxSupportedVersion, _ = version.NewVersion("7.0.0")
)

type Adapter struct {
	baseClient *client.BaseClient

	activeClient  ClientAi
	cfg           *config.Config
	serverVersion version.Version
}

func NewAdapter(cfg *config.Config) (*Adapter, error) {
	baseClient := client.NewBaseClient()

	return &Adapter{baseClient: baseClient, cfg: cfg}, nil
}

func (a *Adapter) InitializeWithRetry(ctx context.Context) error {
	if err := a.Initialize(ctx); err != nil {
		return fmt.Errorf("initialize ai adapter: %w", err)
	}

	if r, ok := a.activeClient.(jwtRetrier); ok {
		r.AddJwtRetry()
	}

	return nil
}

func (a *Adapter) GetDefaultSettings(ctx context.Context) (settings.ScanSettings, error) {
	return a.activeClient.GetDefaultSettings(ctx)
}

func (a *Adapter) SetProjectSettings(ctx context.Context, projectId uuid.UUID, settings *settings.ScanSettings) error {
	return a.activeClient.SetProjectSettings(ctx, projectId, settings)
}

func (a *Adapter) CreateBranch(ctx context.Context, projectId uuid.UUID, branchName, scanTargetPath string) (*uuid.UUID, error) {
	return a.activeClient.CreateBranch(ctx, projectId, branchName, scanTargetPath)
}

func (a *Adapter) CreateProject(ctx context.Context, projectName string) (*uuid.UUID, error) {
	return a.activeClient.CreateProject(ctx, projectName)
}

func (a *Adapter) DeleteProject(ctx context.Context, projectId uuid.UUID) error {
	return a.activeClient.DeleteProject(ctx, projectId)
}

func (a *Adapter) ExistsProject(ctx context.Context, projectName string) (bool, error) {
	return a.activeClient.ExistsProject(ctx, projectName)
}

func (a *Adapter) GetProjectId(ctx context.Context, projectName string) (*uuid.UUID, error) {
	return a.activeClient.GetProjectId(ctx, projectName)
}

func (a *Adapter) GetProjects(ctx context.Context) ([]project.Project, error) {
	return a.activeClient.GetProjects(ctx)
}

func (a *Adapter) GetProject(ctx context.Context, projectId uuid.UUID) (*project.Project, error) {
	return a.activeClient.GetProject(ctx, projectId)
}

func (a *Adapter) GetDefaultTemplateId(ctx context.Context, reportType report.ReportType) (uuid.UUID, error) {
	return a.activeClient.GetDefaultTemplateId(ctx, reportType)
}

func (a *Adapter) GetCustomTemplateId(ctx context.Context, reportName string) (uuid.UUID, error) {
	return a.activeClient.GetCustomTemplateId(ctx, reportName)
}

func (a *Adapter) GetReport(ctx context.Context, projectId, scanResultId, templateId uuid.UUID, includeComments, includeDFD, includeGlossary bool, l10n string) (io.ReadCloser, error) {
	return a.activeClient.GetReport(ctx, projectId, scanResultId, templateId, includeComments, includeDFD, includeGlossary, l10n)
}

func (a *Adapter) GetSbom(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	return a.activeClient.GetSbom(ctx, projectId, scanResultId)
}

func (a *Adapter) GetScanLogs(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	return a.activeClient.GetScanLogs(ctx, projectId, scanResultId)
}

func (a *Adapter) GetBranches(ctx context.Context, projectId uuid.UUID) ([]branch.Branch, error) {
	return a.activeClient.GetBranches(ctx, projectId)
}

func (a *Adapter) GetScans(ctx context.Context, branchId uuid.UUID) ([]scan.Scan, error) {
	return a.activeClient.GetScans(ctx, branchId)
}

func (a *Adapter) GetLastScan(ctx context.Context, branchId uuid.UUID) (*scan.Scan, error) {
	return a.activeClient.GetLastScan(ctx, branchId)
}

func (a *Adapter) GetScan(ctx context.Context, projectId, scanId uuid.UUID) (*scan.Scan, error) {
	return a.activeClient.GetScan(ctx, projectId, scanId)
}

func (a *Adapter) GetScanAiproj(ctx context.Context, projectId, scanSettingsId uuid.UUID) (io.ReadCloser, error) {
	return a.activeClient.GetScanAiproj(ctx, projectId, scanSettingsId)
}

func (a *Adapter) GetScanStage(ctx context.Context, projectId, scanId uuid.UUID) (scanstage.ScanStage, error) {
	return a.activeClient.GetScanStage(ctx, projectId, scanId)
}

func (a *Adapter) GetScanItem(ctx context.Context, id uuid.UUID) (queue.Item, error) {
	return a.activeClient.GetScanItem(ctx, id)
}

func (a *Adapter) StartScanBranch(ctx context.Context, branchId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error) {
	return a.activeClient.StartScanBranch(ctx, branchId, scanLabel, scanType)
}

func (a *Adapter) StartScanProject(ctx context.Context, projectId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error) {
	return a.activeClient.StartScanProject(ctx, projectId, scanLabel, scanType)
}

func (a *Adapter) StopScan(ctx context.Context, scanResultId uuid.UUID) error {
	return a.activeClient.StopScan(ctx, scanResultId)
}

func (a *Adapter) UpdateSources(ctx context.Context, projectId, branchId uuid.UUID, scanTargetPath string) error {
	return a.activeClient.UpdateSources(ctx, projectId, branchId, scanTargetPath)
}

func (a *Adapter) GetVersion(ctx context.Context) (version.Version, error) {
	return a.serverVersion, nil
}

func (a *Adapter) GetHealthcheck(ctx context.Context) (bool, error) {
	return a.activeClient.GetHealthcheck(ctx)
}

func (a *Adapter) CheckLicense(ctx context.Context) error {
	return a.activeClient.CheckLicense(ctx)
}

func (a *Adapter) GetScanStatistic(ctx context.Context, projectId, scanResultId uuid.UUID) (*statistic.Statistic, error) {
	return a.activeClient.GetScanStatistic(ctx, projectId, scanResultId)
}
