package client5x

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
	clientai5x "github.com/POSIdev-community/aictl/pkg/clientai/5_x"
	"github.com/POSIdev-community/aictl/pkg/logger"
	"github.com/google/uuid"
)

type ClientAI5x struct {
	*clientai5x.ClientWithResponses
	jwtClient *clientai5x.ClientWithResponses

	*client.BaseClient
}

func NewAiClient(base *client.BaseClient) *ClientAI5x {
	return &ClientAI5x{
		BaseClient: base,
	}
}

func (a *ClientAI5x) Initialize(ctx context.Context, cfg *config.Config) error {
	client, err := clientai5x.NewClientWithResponses(cfg.UriString(), clientai5x.WithHTTPClient(a.HttpClient))
	if err != nil {
		return fmt.Errorf("new client: %w", err)
	}
	a.ClientWithResponses = client

	a.jwtClient, err = clientai5x.NewClientWithResponses(cfg.UriString(), clientai5x.WithHTTPClient(a.JwtHttpClient))
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

func (a *ClientAI5x) AddJwtRetry() {
	a.HttpClient.Transport = client.NewRetryRoundTripper(a.HttpClient.Transport, http.StatusUnauthorized, a.refreshJWT)

	a.WithRetry = true
}

func (a *ClientAI5x) getJWT(ctx context.Context, cfg *config.Config) error {
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

func (a *ClientAI5x) refreshJWT(ctx context.Context, req *http.Request) error {
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

func (a *ClientAI5x) GetDefaultSettings(ctx context.Context) (settings.ScanSettings, error) {
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
			WebSiteFolder:                         client.GetOrDefault(defaultSettings.DotNetSettings.WebSiteFolder, ""),
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
		PygrepSettings: settings.PygrepSettings{
			RulesDirPath:     client.GetOrDefault(defaultSettings.PygrepSettings.RulesDirPath, ""),
			LaunchParameters: client.GetOrDefault(defaultSettings.PygrepSettings.LaunchParameters, ""),
		},
		ScaSettings: settings.ScaSettings{
			LaunchParameters:       client.GetOrDefault(defaultSettings.ScaSettings.LaunchParameters, ""),
			BuildDependenciesGraph: client.GetOrDefault(defaultSettings.ScaSettings.BuildDependenciesGraph, false),
		},
	}, err
}

func (a *ClientAI5x) SetProjectSettings(ctx context.Context, projectId uuid.UUID, settings *settings.ScanSettings) error {
	if settings == nil {
		return nil
	}

	projectSettings := clientai5x.PutApiProjectsProjectIdSettingsJSONRequestBody{
		ProjectName: &settings.ProjectName,
		Languages: func() *[]clientai5x.LegacyProgrammingLanguageGroup {
			if settings.Languages == nil {
				return nil
			}
			res := make([]clientai5x.LegacyProgrammingLanguageGroup, len(settings.Languages))
			for i := range settings.Languages {
				res[i] = clientai5x.LegacyProgrammingLanguageGroup(settings.Languages[i])
			}
			return &res
		}(),
		WhiteBoxSettings: &clientai5x.WhiteBoxSettingsModel{
			StaticCodeAnalysisEnabled:            &settings.WhiteBoxSettings.StaticCodeAnalysisEnabled,
			PatternMatchingEnabled:               &settings.WhiteBoxSettings.PatternMatchingEnabled,
			SearchForVulnerableComponentsEnabled: &settings.WhiteBoxSettings.SearchForVulnerableComponentsEnabled,
			SearchForConfigurationFlawsEnabled:   &settings.WhiteBoxSettings.SearchForConfigurationFlawsEnabled,
			SearchWithScaEnabled:                 &settings.WhiteBoxSettings.SearchWithScaEnabled,
		},
		DotNetSettings: &clientai5x.DotNetSettingsModel{
			ProjectType:                           client.Reference(clientai5x.DotNetProjectType(settings.DotNetSettings.ProjectType)),
			SolutionFile:                          &settings.DotNetSettings.SolutionFile,
			WebSiteFolder:                         &settings.DotNetSettings.WebSiteFolder,
			LaunchParameters:                      &settings.DotNetSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.DotNetSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.DotNetSettings.DownloadDependencies,
		},
		GoSettings: &clientai5x.GoSettingsModel{
			LaunchParameters:                      &settings.GoSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.GoSettings.UseAvailablePublicAndProtectedMethods,
		},
		JavaScriptSettings: &clientai5x.JavaScriptSettingsModel{
			LaunchParameters:                      &settings.JavaScriptSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.JavaScriptSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.JavaScriptSettings.DownloadDependencies,
			UseTaintAnalysis:                      &settings.JavaScriptSettings.UseTaintAnalysis,
			UseJsaAnalysis:                        &settings.JavaScriptSettings.UseJsaAnalysis,
		},
		JavaSettings: &clientai5x.JavaSettingsModel{
			Parameters:                            &settings.JavaSettings.Parameters,
			UnpackUserPackages:                    &settings.JavaSettings.UnpackUserPackages,
			UserPackagePrefixes:                   &settings.JavaSettings.UserPackagePrefixes,
			Version:                               client.Reference(clientai5x.JavaVersions(settings.JavaSettings.Version)),
			LaunchParameters:                      &settings.JavaSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.JavaSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.JavaSettings.DownloadDependencies,
			DependenciesPath:                      &settings.JavaSettings.DependenciesPath,
		},
		PhpSettings: &clientai5x.PhpSettingsModel{
			LaunchParameters:                      &settings.PhpSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.PhpSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.PhpSettings.DownloadDependencies,
		},
		PmTaintSettings: &clientai5x.PmTaintBaseSettingsModel{
			LaunchParameters:                      &settings.PmTaintSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.PmTaintSettings.UseAvailablePublicAndProtectedMethods,
		},
		PythonSettings: &clientai5x.PythonSettingsModel{
			LaunchParameters:                      &settings.PythonSettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.PythonSettings.UseAvailablePublicAndProtectedMethods,
			DownloadDependencies:                  &settings.PythonSettings.DownloadDependencies,
			DependenciesPath:                      &settings.PythonSettings.DependenciesPath,
		},
		RubySettings: &clientai5x.RubySettingsModel{
			LaunchParameters:                      &settings.RubySettings.LaunchParameters,
			UseAvailablePublicAndProtectedMethods: &settings.RubySettings.UseAvailablePublicAndProtectedMethods,
		},
		PygrepSettings: &clientai5x.PygrepSettingsModel{
			RulesDirPath:     &settings.PygrepSettings.RulesDirPath,
			LaunchParameters: &settings.PygrepSettings.LaunchParameters,
		},
		ScaSettings: &clientai5x.ScaSettingsModel{
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

func (a *ClientAI5x) CreateBranch(ctx context.Context, projectId uuid.UUID, branchName, scanTargetPath string) (*uuid.UUID, error) {
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

func (a *ClientAI5x) CreateProject(ctx context.Context, projectName string) (*uuid.UUID, error) {
	projectUrl := "http://localhost"

	patternMatchingEnabled := true
	searchForConfigurationFlawsEnabled := true
	searchForVulnerableComponentsEnabled := true
	searchWithScaEnabled := false
	staticCodeAnalysisEnabled := true

	projectBaseModel := clientai5x.PostApiProjectsBaseJSONRequestBody{
		Name:       &projectName,
		ProjectUrl: &projectUrl,
		WhiteBox: &clientai5x.WhiteBoxSettingsModel{
			PatternMatchingEnabled:               &patternMatchingEnabled,
			SearchForConfigurationFlawsEnabled:   &searchForConfigurationFlawsEnabled,
			SearchForVulnerableComponentsEnabled: &searchForVulnerableComponentsEnabled,
			SearchWithScaEnabled:                 &searchWithScaEnabled,
			StaticCodeAnalysisEnabled:            &staticCodeAnalysisEnabled,
		},
		Id: &uuid.UUID{},
		Languages: &[]clientai5x.LegacyProgrammingLanguageGroup{
			clientai5x.LegacyProgrammingLanguageGroupGo,
		},
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

func (a *ClientAI5x) DeleteProject(ctx context.Context, projectId uuid.UUID) error {
	response, err := a.DeleteApiProjectsProjectId(ctx, projectId, a.AddJWTToHeader)
	if err != nil {
		return fmt.Errorf("ai adapter delete project request: %w", err)
	}

	if err = CheckResponse(response, "project"); err != nil {
		return fmt.Errorf("ai adapter delete project: %w", err)
	}

	return nil
}

func (a *ClientAI5x) ExistsProject(ctx context.Context, projectName string) (bool, error) {
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

func (a *ClientAI5x) GetProjectId(ctx context.Context, projectName string) (*uuid.UUID, error) {
	response, err := a.GetApiProjectsNameNameWithResponse(ctx, projectName, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get project name exists request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400

	if statusCode == http.StatusBadRequest && errorModel != nil && *errorModel.ErrorCode == clientai5x.ApiErrorTypePROJECTNOTFOUND {
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

func (a *ClientAI5x) GetProjects(ctx context.Context) ([]project.Project, error) {
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
		if *model.ProjectType != clientai5x.Permanent {
			continue
		}

		p := project.NewProject(*model.Id, *model.Name)
		projects = append(projects, p)
	}

	return projects, nil
}

func (a *ClientAI5x) GetProject(ctx context.Context, projectId uuid.UUID) (*project.Project, error) {
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

func (a *ClientAI5x) GetDefaultTemplateId(ctx context.Context, reportType report.ReportType) (uuid.UUID, error) {
	localeId := "ru-Ru"
	params := clientai5x.GetApiReportsTemplatesTypeParams{
		LocaleId: &localeId,
	}

	var aiReportType clientai5x.ReportType
	switch reportType {
	case report.AutoCheck:
		aiReportType = clientai5x.ReportTypeAutoCheck
	case report.Custom:
		aiReportType = clientai5x.ReportTypeCustom
	case report.Gitlab:
		aiReportType = clientai5x.ReportTypeGitlab
	case report.Json:
		aiReportType = clientai5x.ReportTypeJson
	case report.JsonV2:
		return uuid.UUID{}, fmt.Errorf("json v2 report is not supported on Application Inspector 5.x")
	case report.Markdown:
		aiReportType = clientai5x.ReportTypeMd
	case report.Nist:
		aiReportType = clientai5x.ReportTypeNist
	case report.Oud4:
		aiReportType = clientai5x.ReportTypeOud4
	case report.Owasp:
		aiReportType = clientai5x.ReportTypeOwasp
	case report.Owaspm:
		aiReportType = clientai5x.ReportTypeOwaspm
	case report.Pcidss:
		aiReportType = clientai5x.ReportTypePcidss
	case report.PlainReport:
		aiReportType = clientai5x.ReportTypePlainReport
	case report.Sans:
		aiReportType = clientai5x.ReportTypeSans
	case report.Sarif:
		aiReportType = clientai5x.ReportTypeSarif
	case report.Xml:
		aiReportType = clientai5x.ReportTypeXml
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

func (a *ClientAI5x) GetCustomTemplateId(ctx context.Context, reportName string) (uuid.UUID, error) {
	localeId := "ru-RU"
	params := clientai5x.GetApiReportsUserTemplatesNameParams{
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

func (a *ClientAI5x) GetReport(ctx context.Context, projectId, scanResultId, templateId uuid.UUID, includeComments, includeDFD, includeGlossary bool, l10n string) (io.ReadCloser, error) {
	useFilters := false
	sessionId := uuid.New()

	model := clientai5x.ReportGenerateModel{
		LocaleId: &l10n,
		Parameters: &clientai5x.UserReportParametersModel{
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

func (a *ClientAI5x) GetSbom(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	response, err := a.GetApiStoreProjectIdSbomsScanResultId(ctx, projectId, scanResultId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get sbom: %w", err)
	}

	if err = CheckResponse(response, "sbom"); err != nil {
		return nil, fmt.Errorf("ai adapter get sbom: %w", err)
	}

	return response.Body, nil
}

func (a *ClientAI5x) GetScanLogs(ctx context.Context, projectId, scanResultId uuid.UUID) (io.ReadCloser, error) {
	response, err := a.GetApiStoreProjectIdLogsScanResultId(ctx, projectId, scanResultId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get scan logs request: %w", err)
	}

	if err = CheckResponse(response, "logs"); err != nil {
		return nil, fmt.Errorf("ai adapter get scan logs: %w", err)
	}

	return response.Body, nil
}

func (a *ClientAI5x) GetBranches(ctx context.Context, projectId uuid.UUID) ([]branch.Branch, error) {
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

func (a *ClientAI5x) GetScans(ctx context.Context, branchId uuid.UUID) ([]scan.Scan, error) {
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

func (a *ClientAI5x) GetLastScan(ctx context.Context, branchId uuid.UUID) (*scan.Scan, error) {
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

func (a *ClientAI5x) GetScan(ctx context.Context, projectId, scanId uuid.UUID) (*scan.Scan, error) {
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

func (a *ClientAI5x) GetScanAiproj(ctx context.Context, projectId, scanSettingsId uuid.UUID) (io.ReadCloser, error) {
	response, err := a.GetApiProjectsProjectIdScanSettingsScanSettingsIdAiproj(ctx, projectId, scanSettingsId, a.AddJWTToHeader)
	if err != nil {
		return nil, fmt.Errorf("ai adapter get aiproj request: %w", err)
	}

	if err = CheckResponse(response, "aiproj"); err != nil {
		return nil, fmt.Errorf("ai adapter get aiproj: %w", err)
	}

	return response.Body, nil
}

func (a *ClientAI5x) GetScanStage(ctx context.Context, projectId, scanId uuid.UUID) (scanstage.ScanStage, error) {
	response, err := a.GetApiProjectsProjectIdScanResultsScanResultIdProgressWithResponse(ctx, projectId, scanId, a.AddJWTToHeader)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return scanstage.ScanStage{}, err
		}

		return scanstage.ScanStage{}, fmt.Errorf("ai adapter get scan progress request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, body, errorModel); err != nil {
		return scanstage.ScanStage{}, fmt.Errorf("ai adapter get last scan result: %w", err)
	}

	model := *response.JSON200

	return scanstage.ScanStage{
		Value: *model.Value,
		Stage: string(*model.Stage),
	}, nil
}

func (a *ClientAI5x) GetScanItem(ctx context.Context, scanId uuid.UUID) (queue.Item, error) {
	response, err := a.GetApiScansWithResponse(ctx, a.AddJWTToHeader)
	if err != nil {
		return queue.Item{}, fmt.Errorf("ai adapter get scan queue request: %w", err)
	}

	statusCode := response.StatusCode()
	body := string(response.Body)
	if err = CheckResponseByModel(statusCode, body, nil); err != nil {
		return queue.Item{}, fmt.Errorf("ai adapter get scans: %w", err)
	}

	models := *response.JSON200
	sort.Slice(models, func(i, j int) bool {
		first := *models[i].QueuingDateTime
		second := *models[j].QueuingDateTime
		return first.Before(second)
	})

	for i, model := range models {
		if scanId == *model.ScanResultId {
			return queue.Item{
				Place:  i + 1,
				OutOf:  len(models),
				ScanId: scanId,
			}, nil
		}
	}

	return queue.Item{ScanId: scanId}, nil
}

func (a *ClientAI5x) StartScanBranch(ctx context.Context, branchId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error) {
	aiScanType, err := toScanType(scanType)
	if err != nil {
		return uuid.UUID{}, err
	}

	params := clientai5x.StartScanModel{
		ScanType:  &aiScanType,
		ScanLabel: &scanLabel,
	}

	response, err := a.PostApiScansBranchesBranchIdStartWithResponse(ctx, branchId, params, a.AddJWTToHeader)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("start scan branch request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	errorModel := response.JSON400

	if err := CheckResponseByModel(statusCode, responseBody, errorModel); err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter start scan: %w", err)
	}

	scanResultId, err := uuid.Parse(responseBody)
	if err != nil {
		return uuid.UUID{}, err
	}

	return scanResultId, nil
}

func (a *ClientAI5x) StartScanProject(ctx context.Context, projectId uuid.UUID, scanLabel string, scanType scantype.Type) (uuid.UUID, error) {
	aiScanType, err := toScanType(scanType)
	if err != nil {
		return uuid.UUID{}, err
	}

	params := clientai5x.StartScanModel{
		ScanType:  &aiScanType,
		ScanLabel: &scanLabel,
	}

	response, err := a.PostApiScansProjectIdStartWithResponse(ctx, projectId, params, a.AddJWTToHeader)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter start scan request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	errorModel := response.JSON400

	if err := CheckResponseByModel(statusCode, responseBody, errorModel); err != nil {
		return uuid.UUID{}, fmt.Errorf("ai adapter start scan: %w", err)
	}

	scanResultId, err := uuid.Parse(responseBody)
	if err != nil {
		return uuid.UUID{}, err
	}

	return scanResultId, nil
}

func toScanType(scanType scantype.Type) (clientai5x.ScanType, error) {
	switch scanType {
	case scantype.Incremental:
		return clientai5x.Incremental, nil
	case scantype.Full:
		return clientai5x.Full, nil
	default:
		return "", fmt.Errorf("invalid scan type: %d", scanType)
	}
}

func (a *ClientAI5x) StopScan(ctx context.Context, scanResultId uuid.UUID) error {
	response, err := a.PostApiScansScanResultIdStopWithResponse(ctx, scanResultId, a.AddJWTToHeader)
	if err != nil {
		return fmt.Errorf("ai adapter stop scan request: %w", err)
	}

	statusCode := response.StatusCode()
	responseBody := string(response.Body)
	errorModel := response.JSON400
	if err = CheckResponseByModel(statusCode, responseBody, errorModel); err != nil {
		return fmt.Errorf("ai update sources post sources: %w", err)
	}

	return nil
}

func (a *ClientAI5x) UpdateSources(ctx context.Context, projectId, branchId uuid.UUID, scanTargetPath string) error {
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
	params := clientai5x.PostApiStoreProjectIdBranchesBranchIdSourcesParams{Archived: &archived}

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

func (a *ClientAI5x) GetVersion(ctx context.Context) (version.Version, error) {
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

func (a *ClientAI5x) GetHealthcheck(ctx context.Context) (bool, error) {
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

func (a *ClientAI5x) CheckLicense(ctx context.Context) error {
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

func (a *ClientAI5x) GetScanStatistic(ctx context.Context, projectId, scanResultId uuid.UUID) (*statistic.Statistic, error) {
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
