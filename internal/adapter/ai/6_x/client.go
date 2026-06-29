package client6x

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/POSIdev-community/aictl/internal/adapter/ai/client"
	"github.com/POSIdev-community/aictl/internal/core/apperror"
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
	clientai6x "github.com/POSIdev-community/aictl/pkg/clientai/6_x"
	"github.com/POSIdev-community/aictl/pkg/logger"
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
)

type ClientAI6x struct {
	*clientai6x.ClientWithResponses
	jwtClient *clientai6x.ClientWithResponses

	*client.BaseClient
}

func NewAiClient(base *client.BaseClient) *ClientAI6x {
	return &ClientAI6x{
		BaseClient: base,
	}
}

func (a *ClientAI6x) Initialize(ctx context.Context, cfg *config.Config) error {
	client, err := clientai6x.NewClientWithResponses(cfg.UriString(), clientai6x.WithHTTPClient(a.HttpClient))
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	a.ClientWithResponses = client

	a.jwtClient, err = clientai6x.NewClientWithResponses(cfg.UriString(), clientai6x.WithHTTPClient(a.JwtHttpClient))
	if err != nil {
		return fmt.Errorf("new jwt client: %w", err)
	}

	transport := &http.Transport{}
	if cfg.TLSSkip() {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}

		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	a.HttpClient.Transport = transport.Clone()
	a.JwtHttpClient.Transport = transport.Clone()

	if err := a.getJWT(ctx, cfg); err != nil {
		return fmt.Errorf("update jwt: %w", err)
	}

	a.Initialized = true

	return nil
}

func (a *ClientAI6x) AddJwtRetry() {
	a.HttpClient.Transport = client.NewRetryRoundTripper(a.HttpClient.Transport, http.StatusUnauthorized, a.refreshJWT)

	a.WithRetry = true
}

func (a *ClientAI6x) getJWT(ctx context.Context, cfg *config.Config) error {
	if a.Initialized {
		return nil
	}

	response, err := a.jwtClient.GetApiAuthSigninWithResponse(ctx, func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Access-Token", cfg.Token())

		return nil
	})
	if err != nil {
		return fmt.Errorf("get api auth signin: %w", err)
	}

	if err = CheckResponseByModel(response.StatusCode(), string(response.Body), response.JSON400); err != nil {
		return err
	}

	a.AccessToken = *response.JSON200.AccessToken
	a.RefreshToken = *response.JSON200.RefreshToken

	return nil
}

func (a *ClientAI6x) refreshJWT(ctx context.Context, req *http.Request) error {
	log := logger.FromContext(ctx)

	response, err := a.jwtClient.GetApiAuthRefreshTokenWithResponse(ctx, func(ctx context.Context, req *http.Request) error {
		req.Header.Add("Authorization", "Bearer "+a.RefreshToken)

		return nil
	})
	if err != nil {
		return fmt.Errorf("get api auth signin: %w", err)
	}

	if err = CheckResponse(response.HTTPResponse, "jwt refresh"); err != nil {
		return err
	}

	if response.JSON200.AccessToken == nil {
		log.StdErrf("Got empty access token")

		return fmt.Errorf("no access token")
	}

	a.AccessToken = *response.JSON200.AccessToken

	req.Header.Set("Authorization", "Bearer "+a.AccessToken)

	return nil
}

func (a *ClientAI6x) GetDefaultSettings(ctx context.Context) (settings.ScanSettings, error) {
	res, err := a.GetApiProjectsDefaultSettingsWithResponse(ctx, a.AddJWTToHeader)
	if err != nil {
		return settings.ScanSettings{}, fmt.Errorf("get projects default settings request: %w", err)
	}

	statusCode := res.StatusCode()
	responseBody := string(res.Body)
	if err = CheckResponseByModel(statusCode, responseBody, nil); err != nil {
		return settings.ScanSettings{}, fmt.Errorf("get projects default settings: %w", err)
	}

	defaultSettings := *res.JSON200

	return settings.ScanSettings{
		ProjectName: client.GetOrDefault(defaultSettings.Name, ""),
		Languages: func() []string {
			if defaultSettings.Languages == nil {
				return nil
			}

			res := make([]string, len(*defaultSettings.Languages))
			for i := range *defaultSettings.Languages {
				res[i] = string((*defaultSettings.Languages)[i])
			}

			return res
		}(),
		WhiteBoxSettings: settings.WhiteBoxSettings{
			StaticCodeAnalysisEnabled:            client.GetOrDefault(defaultSettings.WhiteBox.StaticCodeAnalysisEnabled, false),
			PatternMatchingEnabled:               client.GetOrDefault(defaultSettings.WhiteBox.PatternMatchingEnabled, false),
			SearchForVulnerableComponentsEnabled: client.GetOrDefault(defaultSettings.WhiteBox.SearchForVulnerableComponentsEnabled, false),
			SearchForConfigurationFlawsEnabled:   client.GetOrDefault(defaultSettings.WhiteBox.SearchForConfigurationFlawsEnabled, false),
			SearchWithScaEnabled:                 client.GetOrDefault(defaultSettings.WhiteBox.SearchWithScaEnabled, false),
		},
		DotNetSettings: settings.DotNetSettings{
			ProjectType:                           string(client.GetOrDefault(defaultSettings.DotNetSettings.ProjectType, "")),
			SolutionFile:                          client.GetOrDefault(defaultSettings.DotNetSettings.SolutionFile, ""),
			LaunchParameters:                      client.GetOrDefault(defaultSettings.DotNetSettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.DotNetSettings.UseAvailablePublicAndProtectedMethods, false),
			DownloadDependencies:                  client.GetOrDefault(defaultSettings.DotNetSettings.DownloadDependencies, false),
		},
		GoSettings: settings.GoSettings{
			LaunchParameters:                      client.GetOrDefault(defaultSettings.GoSettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.GoSettings.UseAvailablePublicAndProtectedMethods, false),
		},
		JavaScriptSettings: settings.JavaScriptSettings{
			LaunchParameters:                      client.GetOrDefault(defaultSettings.JavaScriptSettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.JavaScriptSettings.UseAvailablePublicAndProtectedMethods, false),
			DownloadDependencies:                  client.GetOrDefault(defaultSettings.JavaScriptSettings.DownloadDependencies, false),
			UseTaintAnalysis:                      client.GetOrDefault(defaultSettings.JavaScriptSettings.UseTaintAnalysis, false),
			UseJsaAnalysis:                        client.GetOrDefault(defaultSettings.JavaScriptSettings.UseJsaAnalysis, false),
		},
		JavaSettings: settings.JavaSettings{
			Parameters:                            client.GetOrDefault(defaultSettings.JavaSettings.Parameters, ""),
			UnpackUserPackages:                    client.GetOrDefault(defaultSettings.JavaSettings.UnpackUserPackages, false),
			UserPackagePrefixes:                   client.GetOrDefault(defaultSettings.JavaSettings.UserPackagePrefixes, ""),
			Version:                               string(client.GetOrDefault(defaultSettings.JavaSettings.Version, "")),
			LaunchParameters:                      client.GetOrDefault(defaultSettings.JavaSettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.JavaSettings.UseAvailablePublicAndProtectedMethods, false),
			DownloadDependencies:                  client.GetOrDefault(defaultSettings.JavaSettings.DownloadDependencies, false),
			DependenciesPath:                      client.GetOrDefault(defaultSettings.JavaSettings.DependenciesPath, ""),
		},
		PhpSettings: settings.PhpSettings{
			LaunchParameters:                      client.GetOrDefault(defaultSettings.PhpSettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.PhpSettings.UseAvailablePublicAndProtectedMethods, false),
			DownloadDependencies:                  client.GetOrDefault(defaultSettings.PhpSettings.DownloadDependencies, false),
		},
		PmTaintSettings: settings.PmTaintSettings{
			LaunchParameters:                      client.GetOrDefault(defaultSettings.PmTaintSettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.PmTaintSettings.UseAvailablePublicAndProtectedMethods, false),
		},
		PythonSettings: settings.PythonSettings{
			LaunchParameters:                      client.GetOrDefault(defaultSettings.PythonSettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.PythonSettings.UseAvailablePublicAndProtectedMethods, false),
			DownloadDependencies:                  client.GetOrDefault(defaultSettings.PythonSettings.DownloadDependencies, false),
			DependenciesPath:                      client.GetOrDefault(defaultSettings.PythonSettings.DependenciesPath, ""),
		},
		RubySettings: settings.RubySettings{
			LaunchParameters:                      client.GetOrDefault(defaultSettings.RubySettings.LaunchParameters, ""),
			UseAvailablePublicAndProtectedMethods: client.GetOrDefault(defaultSettings.RubySettings.UseAvailablePublicAndProtectedMethods, false),
		},
		ScaSettings: settings.ScaSettings{
			LaunchParameters:       client.GetOrDefault(defaultSettings.ScaSettings.LaunchParameters, ""),
			BuildDependenciesGraph: client.GetOrDefault(defaultSettings.ScaSettings.BuildDependenciesGraph, false),
		},
	}, err
}

func (a *ClientAI6x) SetProjectSettings(ctx context.Context, projectId uuid.UUID, settings *settings.ScanSettings) error {
	if settings == nil {
		return nil
	}

	priority := clientai6x.PriorityLow
	projectSettings := clientai6x.PutApiProjectsProjectIdSettingsJSONRequestBody{
		ProjectName: &settings.ProjectName,
		Priority:    &priority,
		Languages: func() *[]clientai6x.LegacyProgrammingLanguageGroup {
			if settings.Languages == nil {
				return nil
			}
			res := make([]clientai6x.LegacyProgrammingLanguageGroup, len(settings.Languages))
			for i := range settings.Languages {
				res[i] = clientai6x.LegacyProgrammingLanguageGroup(settings.Languages[i])
			}
			return &res
		}(),
		WhiteBoxSettings: &clientai6x.WhiteBoxSettingsModel{
			StaticCodeAnalysisEnabled:            &settings.WhiteBoxSettings.StaticCodeAnalysisEnabled,
			PatternMatchingEnabled:               &settings.WhiteBoxSettings.PatternMatchingEnabled,
			SearchForVulnerableComponentsEnabled: &settings.WhiteBoxSettings.SearchForVulnerableComponentsEnabled,
			SearchForConfigurationFlawsEnabled:   &settings.WhiteBoxSettings.SearchForConfigurationFlawsEnabled,
			SearchWithScaEnabled:                 &settings.WhiteBoxSettings.SearchWithScaEnabled,
		},
		DotNetSettings: &clientai6x.DotNetSettingsModel{
			ProjectType:                           client.Reference(clientai6x.DotNetProjectType(settings.DotNetSettings.ProjectType)),
			SolutionFile:                          &settings.DotNetSettings.SolutionFile,
			LaunchParameters:                      &settings.DotNetSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.DotNetSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.DotNetSettings.DownloadDependencies,
		},
		GoSettings: &clientai6x.GoSettingsModel{
			LaunchParameters:                      &settings.GoSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.GoSettings.UseAvailablePublicAndProtectedMethods,
		},
		JavaScriptSettings: &clientai6x.JavaScriptSettingsModel{
			LaunchParameters:                      &settings.JavaScriptSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.JavaScriptSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.JavaScriptSettings.DownloadDependencies,
			UseTaintAnalysis:                      &settings.JavaScriptSettings.UseTaintAnalysis,
			UseJsaAnalysis:                        &settings.JavaScriptSettings.UseJsaAnalysis,
		},
		JavaSettings: &clientai6x.JavaSettingsModel{
			Parameters:                            &settings.JavaSettings.Parameters,
			UnpackUserPackages:                    &settings.JavaSettings.UnpackUserPackages,
			UserPackagePrefixes:                   &settings.JavaSettings.UserPackagePrefixes,
			Version:                               client.Reference(clientai6x.JavaVersions(settings.JavaSettings.Version)),
			LaunchParameters:                      &settings.JavaSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.JavaSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.JavaSettings.DownloadDependencies,
			DependenciesPath:                      &settings.JavaSettings.DependenciesPath,
		},
		PhpSettings: &clientai6x.PhpSettingsModel{
			LaunchParameters:                      &settings.PhpSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.PhpSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.PhpSettings.DownloadDependencies,
		},
		PmTaintSettings: &clientai6x.PmTaintBaseSettingsModel{
			LaunchParameters:                      &settings.PmTaintSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.PmTaintSettings.UseAvailablePublicAndProtectedMethods,
		},
		PythonSettings: &clientai6x.PythonSettingsModel{
			LaunchParameters:                      &settings.PythonSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.PythonSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.PythonSettings.DownloadDependencies,
			DependenciesPath:                      &settings.PythonSettings.DependenciesPath,
		},
		RubySettings: &clientai6x.RubySettingsModel{
			LaunchParameters:                      &settings.RubySettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.RubySettings.UseAvailablePublicAndProtectedMethods,
		},
		ScaSettings: &clientai6x.ScaSettingsModel{
			LaunchParameters:       &settings.ScaSettings.LaunchParameters,
			BuildDependenciesGraph: &settings.ScaSettings.BuildDependenciesGraph,
		},
	}

	res, err := a.PutApiProjectsProjectIdSettingsWithResponse(ctx, projectId, projectSettings, a.AddJWTToHeader)
	if err != nil {
		return fmt.Errorf("put project settings request: %w", err)
	}

	statusCode := res.StatusCode()
	responseBody := string(res.Body)
	errorModel := res.JSON400
	if err = CheckResponseByModel(statusCode, responseBody, errorModel); err != nil {
		return fmt.Errorf("put project settings: %w", err)
	}

	return nil
}

func (a *ClientAI6x) CreateBranch(ctx context.Context, projectId uuid.UUID, branchName, scanTargetPath string) (*uuid.UUID, error) {
	useStubSources := scanTargetPath == ""
	if useStubSources {
		var err error
		scanTargetPath, err = client.CreateStubScanTarget()
		if err != nil {
			return nil, err
		}
	}

	archivePath, err := client.PrepareArchive(scanTargetPath)
	if archivePath != scanTargetPath {
		defer func() {
			_ = os.Remove(archivePath)
		}()
	}
	if err != nil {
		return nil, err
	}

	body, contentType, err := client.PrepareMultipartBody(ctx, archivePath, !useStubSources, client.MultipartField{Key: "Name", Value: branchName})
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = body.Close()
	}()

	response, err := a.PostApiStoreProjectProjectIdBranchesArchiveWithBodyWithResponse(ctx, projectId, contentType, body, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("create upload session response error: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, responseBody, errorModel); err != nil {
		return nil, err
	}

	id := string(response.Body)
	branchId, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}

	return &branchId, nil
}

func (a *ClientAI6x) CreateProject(ctx context.Context, projectName string) (*uuid.UUID, error) {
	projectUrl := "http://localhost"

	patternMatchingEnabled := true
	searchForConfigurationFlawsEnabled := true
	searchForVulnerableComponentsEnabled := true
	searchWithScaEnabled := false
	staticCodeAnalysisEnabled := true
	preferredAgentsOnly := false
	preferredAgents := []openapi_types.UUID{}
	priority := clientai6x.PriorityLow

	projectBaseModel := clientai6x.PostApiProjectsBaseJSONRequestBody{
		Name:       &projectName,
		ProjectUrl: &projectUrl,
		WhiteBox: &clientai6x.WhiteBoxSettingsModel{
			PatternMatchingEnabled:               &patternMatchingEnabled,
			SearchForConfigurationFlawsEnabled:   &searchForConfigurationFlawsEnabled,
			SearchForVulnerableComponentsEnabled: &searchForVulnerableComponentsEnabled,
			SearchWithScaEnabled:                 &searchWithScaEnabled,
			StaticCodeAnalysisEnabled:            &staticCodeAnalysisEnabled,
		},
		Id: &uuid.UUID{},
		Languages: &[]clientai6x.LegacyProgrammingLanguageGroup{
			clientai6x.LegacyProgrammingLanguageGroupGo,
		},
		PreferredAgentsSettings: &clientai6x.PreferredAgentsSettings{
			PreferredAgents:     &preferredAgents,
			PreferredAgentsOnly: preferredAgentsOnly,
		},
		Priority: &priority,
	}

	createProjectResponse, err := a.PostApiProjectsBaseWithResponse(ctx, projectBaseModel, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("create project request error: %w", err)
	}

	statusCode := createProjectResponse.StatusCode()
	body := string(createProjectResponse.Body)
	errorModel := createProjectResponse.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return nil, err
	}

	projectId, err := uuid.Parse(body)
	if err != nil {
		return nil, err
	}

	return &projectId, nil
}

func (a *ClientAI6x) DeleteProject(ctx context.Context, projectId uuid.UUID) error {
	response, err := a.DeleteApiProjectsProjectId(ctx, projectId, a.AddJWTToHeader)
	if err != nil {
		return fmt.Errorf("ai adapter delete project request: %w", err)
	}

	if err = CheckResponse(response, "project"); err != nil {
		return fmt.Errorf("ai adapter delete project: %w", err)
	}

	return nil
}

func (a *ClientAI6x) ExistsProject(ctx context.Context, projectName string) (bool, error) {
	response, err := a.GetApiProjectsNameExistsWithResponse(ctx, projectName, a.AddJWTToHeader)
	if err != nil {
		return false, fmt.Errorf("ai adapter get project name exists request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return false, err
	}

	boolValueTrue, err := strconv.ParseBool(body)
	if err != nil {
		return false, err
	}

	return boolValueTrue, nil
}

func (a *ClientAI6x) GetProjectId(ctx context.Context, projectName string) (*uuid.UUID, error) {
	response, err := a.GetApiProjectsNameNameWithResponse(ctx, projectName, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get project name exists request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400

	if statusCode == http.StatusBadRequest && errorModel != nil && *errorModel.ErrorCode == clientai6x.ApiErrorTypePROJECTNOTFOUND {
		return nil, nil
	}

	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("ai adapter get project name exists: %w", err)
	}

	proj := *response.JSON200

	return proj.Id, nil
}

func (a *ClientAI6x) GetProjects(ctx context.Context) ([]project.Project, error) {
	log := logger.FromContext(ctx)

	log.StdErrf("Send get projects request")

	response, err := a.GetApiProjectsWithResponse(ctx, nil, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get projects request request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	if err = CheckResponseByModel(statusCode, body, nil); err != nil {
		return nil, fmt.Errorf("ai adapter get projects response: %w", err)
	}

	models := *response.JSON200
	projects := make([]project.Project, 0, len(models))

	for _, model := range models {
		if *model.ProjectType != clientai6x.Permanent {
			continue
		}

		p := project.NewProject(*model.Id, *model.Name)
		projects = append(projects, p)
	}

	return projects, nil
}

func (a *ClientAI6x) GetProject(ctx context.Context, projectId uuid.UUID) (*project.Project, error) {
	response, err := a.GetApiProjectsProjectIdWithResponse(ctx, projectId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get projects request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return nil, fmt.Errorf("ai adapter get project: %w", err)
	}

	model := response.JSON200
	p := project.NewProject(*model.Id, *model.Name)

	return &p, nil
}

func (a *ClientAI6x) GetDefaultTemplateId(ctx context.Context, reportType report.ReportType) (uuid.UUID, error) {
	localeId := "ru-Ru"
	params := clientai6x.GetApiReportsTemplatesTypeParams{
		LocaleId: &localeId,
	}

	var aiReportType clientai6x.ReportType
	switch reportType {
	case report.AutoCheck:
		aiReportType = clientai6x.ReportTypeAutoCheck
	case report.Custom:
		aiReportType = clientai6x.ReportTypeCustom
	case report.Gitlab:
		aiReportType = clientai6x.ReportTypeGitlab
	case report.Json:
		aiReportType = clientai6x.ReportTypeJson
	case report.JsonV2:
		aiReportType = clientai6x.ReportTypeJsonV2
	case report.Markdown:
		aiReportType = clientai6x.ReportTypeMd
	case report.Nist:
		aiReportType = clientai6x.ReportTypeNist
	case report.Oud4:
		aiReportType = clientai6x.ReportTypeOud4
	case report.Owasp:
		aiReportType = clientai6x.ReportTypeOwasp
	case report.Owaspm:
		aiReportType = clientai6x.ReportTypeOwaspm
	case report.Pcidss:
		aiReportType = clientai6x.ReportTypePcidss
	case report.PlainReport:
		aiReportType = clientai6x.ReportTypePlainReport
	case report.Sans:
		aiReportType = clientai6x.ReportTypeSans
	case report.Sarif:
		aiReportType = clientai6x.ReportTypeSarif
	case report.Xml:
		return uuid.UUID{}, fmt.Errorf("xml report is not supported on Application Inspector 6.x")
	default:
		return uuid.UUID{}, fmt.Errorf("invalid reportType: %s", reportType)
	}

	response, err := a.GetApiReportsTemplatesType(ctx, aiReportType, &params, a.AddJWTToHeader)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter get default template id request: %w", err)
	}

	if err = CheckResponse(response, "template"); err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter get template id: %w", err)
	}

	bodyBytes, err := io.ReadAll(response.Body)
	defer func() { _ = response.Body.Close() }()
	if err != nil {
		return uuid.UUID{}, err
	}

	if !strings.Contains(response.Header.Get("Content-Type"), "json") && response.StatusCode == 200 {
		return uuid.UUID{}, fmt.Errorf("ai adapter response not 200 and json")
	}

	type ReportTemplateSimpleModel struct {
		Id *uuid.UUID `json:"id,omitempty"`
	}

	var dest ReportTemplateSimpleModel
	if err := json.Unmarshal(bodyBytes, &dest); err != nil {
		return uuid.UUID{}, err
	}

	return *dest.Id, nil
}

func (a *ClientAI6x) GetCustomTemplateId(ctx context.Context, reportName string) (uuid.UUID, error) {
	localeId := "ru-RU"
	params := clientai6x.GetApiReportsUserTemplatesNameParams{
		LocaleId: &localeId,
	}

	response, err := a.GetApiReportsUserTemplatesName(ctx, reportName, &params, a.AddJWTToHeader)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter get custom template id request: %w", err)
	}

	if err = CheckResponse(response, "template"); err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter get template id: %w", err)
	}

	bodyBytes, err := io.ReadAll(response.Body)
	defer func() { _ = response.Body.Close() }()
	if err != nil {
		return uuid.UUID{}, err
	}

	if !strings.Contains(response.Header.Get("Content-Type"), "json") && response.StatusCode == 200 {
		return uuid.UUID{}, fmt.Errorf("ai adapter response not 200 and json")
	}

	type ReportTemplateSimpleModel struct {
		Id *uuid.UUID `json:"id,omitempty"`
	}

	var model ReportTemplateSimpleModel
	if err := json.Unmarshal(bodyBytes, &model); err != nil {
		return uuid.UUID{}, err
	}

	return *model.Id, nil
}

func (a *ClientAI6x) GetReport(ctx context.Context, projectId, scanResultId, templateId uuid.UUID, includeComments, includeDFD, includeGlossary bool, l10n string) (io.ReadCloser, error) {
	useFilters := false
	sessionId := uuid.New()

	model := clientai6x.ReportGenerateModel{
		LocaleId: &l10n,
		Parameters: &clientai6x.UserReportParametersModel{
			IncludeComments:  &includeComments,
			IncludeDFD:       &includeDFD,
			IncludeGlossary:  &includeGlossary,
			ReportTemplateId: &templateId,
			UseFilters:       &useFilters,
		},
		ProjectId:    &projectId,
		ScanResultId: &scanResultId,
		SessionId:    &sessionId,
	}

	response, err := a.PostApiReportsGenerate(ctx, model, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter generate report request: %w", err)
	}

	if err = CheckResponse(response, "report"); err != nil {
		return nil, fmt.Errorf("ai adapter generate report: %w", err)
	}

	return response.Body, nil
}

func (a *ClientAI6x) GetSbom(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	response, err := a.GetApiStoreProjectIdSbomsScanResultId(ctx, projectId, scanResultId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get sbom: %w", err)
	}

	if err = CheckResponse(response, "sbom"); err != nil {
		return nil, fmt.Errorf("ai adapter get sbom: %w", err)
	}

	return response.Body, nil
}

func (a *ClientAI6x) GetScanLogs(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	response, err := a.GetApiStoreProjectIdLogsScanResultId(ctx, projectId, scanResultId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get scan logs request: %w", err)
	}

	if err = CheckResponse(response, "logs"); err != nil {
		return nil, fmt.Errorf("ai adapter get scan logs: %w", err)
	}

	return response.Body, nil
}

func (a *ClientAI6x) GetBranches(ctx context.Context, projectId uuid.UUID) ([]branch.Branch, error) {
	getBranchesResponse, err := a.GetApiProjectsProjectIdBranchesWithResponse(ctx, projectId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get branch request: %w", err)
	}

	statusCode := getBranchesResponse.StatusCode()
	body := string(getBranchesResponse.Body)
	errorModel := getBranchesResponse.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return nil, fmt.Errorf("ai adapter get branches: %w", err)
	}

	branchModels := *getBranchesResponse.JSON200

	branches := make([]branch.Branch, len(branchModels))
	for i, model := range branchModels {
		if model.Description == nil {
			description := ""
			model.Description = &description
		}
		branches[i] = branch.NewBranch(*model.Id, *model.Name, *model.Description, *model.IsWorking)
	}

	return branches, nil
}

func (a *ClientAI6x) GetScans(ctx context.Context, branchId uuid.UUID) ([]scan.Scan, error) {
	response, err := a.GetApiBranchesBranchIdScanResultsWithResponse(ctx, branchId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get scan results request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return nil, fmt.Errorf("ai adapter get scans: %w", err)
	}

	models := *response.JSON200
	scans := make([]scan.Scan, 0, len(models))
	for _, model := range models {
		if model.Id == nil || model.SettingsId == nil {
			continue
		}

		scans = append(scans, scan.NewScan(uuid.UUID(*model.Id), uuid.UUID(*model.SettingsId), model.ScanDate, model.ScanLabel))
	}

	return scans, nil
}

func (a *ClientAI6x) GetLastScan(ctx context.Context, branchId uuid.UUID) (*scan.Scan, error) {
	response, err := a.GetApiBranchesBranchIdScanResultsLastWithResponse(ctx, branchId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get last scan result request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return nil, fmt.Errorf("ai adapter get last scan result: %w", err)
	}

	model := response.JSON200
	if model.Id == nil || model.SettingsId == nil {
		return nil, apperror.NewEmptyResponseError("last scan result")
	}

	scanResult := scan.NewScan(uuid.UUID(*model.Id), uuid.UUID(*model.SettingsId), model.ScanDate, model.ScanLabel)

	return &scanResult, nil
}

func (a *ClientAI6x) GetScan(ctx context.Context, projectId, scanId uuid.UUID) (*scan.Scan, error) {
	response, err := a.GetApiProjectsProjectIdScanResultsScanResultIdWithResponse(ctx, projectId, scanId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get scan request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return nil, fmt.Errorf("ai adapter get scan aiproj: %w", err)
	}

	model := response.JSON200
	if model.Id == nil || model.SettingsId == nil {
		return nil, apperror.NewEmptyResponseError("scan")
	}

	scanResult := scan.NewScan(uuid.UUID(*model.Id), uuid.UUID(*model.SettingsId), model.ScanDate, model.ScanLabel)

	return &scanResult, nil
}

func (a *ClientAI6x) GetScanAiproj(ctx context.Context, projectId, scanSettingsId uuid.UUID) (io.ReadCloser, error) {
	response, err := a.GetApiProjectsProjectIdScanSettingsScanSettingsIdAiproj(ctx, projectId, scanSettingsId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get aiproj request: %w", err)
	}

	if err = CheckResponse(response, "aiproj"); err != nil {
		return nil, fmt.Errorf("ai adapter get aiproj: %w", err)
	}

	return response.Body, nil
}

func scanProgressFromModel(model *clientai6x.ScanProgressModel) (scanstage.ScanStage, bool) {
	if model == nil || model.Stage == nil {
		return scanstage.ScanStage{}, false
	}

	stage := scanstage.ScanStage{
		Stage: string(*model.Stage),
	}
	if model.Value != nil {
		stage.Value = *model.Value
	}
	if model.SubStage != nil {
		stage.SubStage = *model.SubStage
	}

	return stage, true
}

func (a *ClientAI6x) GetScanStage(ctx context.Context, projectId, scanId uuid.UUID) (scanstage.ScanStage, error) {
	response, err := a.GetApiProjectsProjectIdScanResultsScanResultIdProgressWithResponse(ctx, projectId, scanId, a.AddJWTToHeader)
	if err == nil {
		statusCode := response.StatusCode()
		body := string(response.Body)
		errorModel := response.JSON400
		if err = CheckResponseByModel(statusCode, body, errorModel); err == nil {
			if stage, ok := scanProgressFromModel(response.JSON200); ok {
				return stage, nil
			}
		}
	}

	scanResponse, err := a.GetApiProjectsProjectIdScanResultsScanResultIdWithResponse(ctx, projectId, scanId, a.AddJWTToHeader)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return scanstage.ScanStage{}, err
		}

		return scanstage.ScanStage{}, fmt.Errorf("ai adapter get scan result request: %w", err)
	}

	statusCode := scanResponse.StatusCode()
	body := string(scanResponse.Body)
	errorModel := scanResponse.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return scanstage.ScanStage{}, fmt.Errorf("ai adapter get scan result: %w", err)
	}

	if stage, ok := scanProgressFromModel(scanResponse.JSON200.Progress); ok {
		return stage, nil
	}

	return scanstage.ScanStage{}, apperror.NewEmptyResponseError("scan progress")
}

func (a *ClientAI6x) GetScanItem(ctx context.Context, id uuid.UUID) (queue.Item, error) {
	if item, found, err := a.findScanQueueItem(ctx, id); err != nil {
		return queue.Item{}, err
	} else if found {
		return item, nil
	}

	return a.getScanQueueItemByID(ctx, id)
}

func (a *ClientAI6x) getScanQueueItemByID(ctx context.Context, id uuid.UUID) (queue.Item, error) {
	response, err := a.GetItemWithResponse(ctx, id, a.AddJWTToHeader)
	if err != nil {
		return queue.Item{}, fmt.Errorf("ai adapter get scan queue item request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	if err = CheckResponseByModel(statusCode, body, response.JSON400); err != nil {
		if apperror.IsApiErrorCode(err, string(clientai6x.ApiErrorTypeEMPTYSCANRESULT)) {
			time.Sleep(1 * time.Second)
			return a.getScanQueueItemByID(ctx, id)
		}
		if apperror.IsApiErrorCode(err, string(clientai6x.ApiErrorTypeQUEUEITEMNOTFOUND)) ||
			apperror.IsApiErrorCode(err, string(clientai6x.ApiErrorTypeQUEUEITEMALREADYASSIGNEDTOAGENT)) {
			return queue.Item{ScanId: id}, nil
		}

		return queue.Item{}, fmt.Errorf("ai adapter get scan queue item: %w", err)
	}

	if response.JSON200 == nil {
		return queue.Item{}, apperror.NewEmptyResponseError("scan queue item")
	}

	dto := response.JSON200

	return queue.Item{
		Place:  int(dto.Position),
		ScanId: dto.ScanResultId,
	}, nil
}

func (a *ClientAI6x) findScanQueueItem(ctx context.Context, id uuid.UUID) (queue.Item, bool, error) {
	response, err := a.GetAllItemsWithResponse(ctx, a.AddJWTToHeader)
	if err != nil {
		return queue.Item{}, false, fmt.Errorf("ai adapter get scan queue items request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	if err = CheckResponseByModel(statusCode, body, response.JSON400); err != nil {
		return queue.Item{}, false, fmt.Errorf("ai adapter get scan queue items: %w", err)
	}

	if response.JSON200 == nil {
		return queue.Item{}, false, apperror.NewEmptyResponseError("scan queue items")
	}

	models := *response.JSON200
	sort.Slice(models, func(i, j int) bool {
		return models[i].QueueDateTime < models[j].QueueDateTime
	})

	for i, model := range models {
		if id == model.Id || id == model.ScanResultId {
			return queue.Item{
				Place:  i + 1,
				OutOf:  len(models),
				ScanId: model.ScanResultId,
			}, true, nil
		}
	}

	return queue.Item{}, false, nil
}

func (a *ClientAI6x) createScanQueueItem(ctx context.Context, branchId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error) {
	scope, err := toScope(scanType)
	if err != nil {
		return uuid.UUID{}, err
	}

	params := clientai6x.CreateQueueItem{
		BranchId:  branchId,
		Scope:     scope,
		ScanLabel: &scanLabel,
	}

	response, err := a.CreateItemWithResponse(ctx, params, a.AddJWTToHeader)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("create scan queue item request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	if err := CheckResponseByModel(statusCode, responseBody, response.JSON400); err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter start scan: %w", err)
	}

	if response.JSON200 == nil {
		return uuid.UUID{}, apperror.NewEmptyResponseError("scan result id")
	}

	return *response.JSON200, nil
}

func (a *ClientAI6x) StartScanBranch(ctx context.Context, branchId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error) {
	taskId, err := a.createScanQueueItem(ctx, branchId, scanLabel, scanType)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter start scan: %w", err)
	}

	item, err := a.GetScanItem(ctx, taskId)
	if err != nil {
		return uuid.UUID{}, err
	}
	if item.ScanId != uuid.Nil && item.ScanId != taskId {
		return item.ScanId, nil
	}
	if item.OutOf > 0 {
		return item.ScanId, nil
	}

	lastScan, lastErr := a.GetLastScan(ctx, branchId)
	if lastErr != nil {
		return uuid.UUID{}, fmt.Errorf("scan queue item unavailable, get last scan: %w", lastErr)
	}

	return lastScan.Id, nil
}

func (a *ClientAI6x) StartScanProject(ctx context.Context, projectId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error) {
	branches, err := a.GetBranches(ctx, projectId)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("get branches for project scan: %w", err)
	}
	if len(branches) == 0 {
		return uuid.UUID{}, fmt.Errorf("no branches found for project")
	}

	branchId := branches[0].Id
	for _, b := range branches {
		if b.IsWorking {
			branchId = b.Id
			break
		}
	}

	return a.createScanQueueItem(ctx, branchId, scanLabel, scanType)
}

func toScope(scanType scantype.Type) (clientai6x.Scope, error) {
	switch scanType {
	case scantype.Incremental:
		return clientai6x.ScopeIncremental, nil
	case scantype.Full:
		return clientai6x.ScopeFull, nil
	default:
		return "", fmt.Errorf("invalid scan type: %d", scanType)
	}
}

func (a *ClientAI6x) StopScan(ctx context.Context, scanResultId uuid.UUID) error {
	response, err := a.StopScanWithResponse(ctx, scanResultId, a.AddJWTToHeader)
	if err != nil {
		return fmt.Errorf("ai adapter stop scan request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	if err = CheckResponseByModel(statusCode, responseBody, response.JSON400); err != nil {
		return fmt.Errorf("ai adapter stop scan: %w", err)
	}

	return nil
}

func (a *ClientAI6x) UpdateSources(ctx context.Context, projectId, branchId uuid.UUID, scanTargetPath string) error {
	log := logger.FromContext(ctx)

	archivePath, err := client.PrepareArchive(scanTargetPath)
	if archivePath != scanTargetPath {
		defer func() {
			_ = os.Remove(archivePath)
		}()
	}
	if err != nil {
		return err
	}

	if fi, err := os.Stat(archivePath); err == nil {
		log.StdErrf("archive prepared, size: %.1f MB", float64(fi.Size())/(1024*1024))
	}

	body, contentType, err := client.PrepareMultipartBody(ctx, archivePath, true)
	if err != nil {
		return err
	}
	defer func() {
		_ = body.Close()
	}()

	archived := true
	params := clientai6x.PostApiStoreProjectIdBranchesBranchIdSourcesParams{Archived: &archived}

	response, err := a.PostApiStoreProjectIdBranchesBranchIdSourcesWithBodyWithResponse(ctx, projectId, branchId, &params, contentType, body, a.AddJWTToHeader)
	if err != nil {
		return fmt.Errorf("ai update sources request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, responseBody, errorModel); err != nil {
		return fmt.Errorf("ai update sources post sources: %w", err)
	}

	return nil
}

func (a *ClientAI6x) GetVersion(ctx context.Context) (version.Version, error) {
	response, err := a.GetApiVersionsPackageCurrentWithResponse(ctx, a.AddJWTToHeader)
	if err != nil {
		return version.Version{}, fmt.Errorf("ai get version request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	if err = CheckResponseByModel(statusCode, responseBody, nil); err != nil {
		return version.Version{}, fmt.Errorf("ai get version: %w", err)
	}

	v, err := version.NewVersion(responseBody)
	if err != nil {
		return version.Version{}, fmt.Errorf("new version: %w", err)
	}

	return v, nil
}

func (a *ClientAI6x) GetHealthcheck(ctx context.Context) (bool, error) {
	response, err := a.GetHealthSummaryWithResponse(ctx, a.AddJWTToHeader)
	if err != nil {
		return false, fmt.Errorf("ai get version request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	if err = CheckResponseByModel(statusCode, responseBody, nil); err != nil {
		return false, fmt.Errorf("ai get version: %w", err)
	}

	health := true
	for _, service := range *response.JSON200.Services {
		health = health && *service.Status == "Healthy"
	}

	return health, nil
}

func (a *ClientAI6x) CheckLicense(ctx context.Context) error {
	response, err := a.GetApiLicenseWithResponse(ctx, a.AddJWTToHeader)
	if err != nil {
		return fmt.Errorf("ai check license request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	if err = CheckResponseByModel(statusCode, responseBody, nil); err != nil {
		return fmt.Errorf("ai check license: %w", err)
	}

	if !*response.JSON200.IsValid {
		return fmt.Errorf("license is invalid")
	}

	return nil
}

func (a *ClientAI6x) GetScanStatistic(ctx context.Context, projectId, scanResultId uuid.UUID) (*statistic.Statistic, error) {
	response, err := a.GetApiProjectsProjectIdScanResultsScanResultIdStatisticWithResponse(ctx, projectId, scanResultId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai get scan statistic request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	if err = CheckResponseByModel(statusCode, responseBody, nil); err != nil {
		return nil, fmt.Errorf("ai get scan statistic: %w", err)
	}

	model := response.JSON200

	return &statistic.Statistic{
		Total:     *model.Total,
		High:      *model.High,
		Medium:    *model.Medium,
		Low:       *model.Low,
		Potential: *model.Potential,
	}, nil
}
