//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type pipelineMeta struct {
	ProjectID  string `json:"project_id"`
	BranchID   string `json:"branch_id"`
	ScanID     string `json:"scan_id"`
	AIEVersion string `json:"aie_version"`
}

func loadMeta(t *testing.T, path string) pipelineMeta {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err, "read meta.json")

	var meta pipelineMeta
	require.NoError(t, json.Unmarshal(data, &meta), "parse meta.json")

	return meta
}

func assertUUID(t *testing.T, value string) {
	t.Helper()

	_, err := uuid.Parse(strings.TrimSpace(value))
	require.NoError(t, err, "expected UUID, got %q", value)
}

func assertVersionMajor(t *testing.T, version, expectedMajor string) {
	t.Helper()

	version = strings.TrimSpace(version)
	require.NotEmpty(t, version, "aie version is empty")

	parts := strings.SplitN(version, ".", 2)
	require.NotEmpty(t, parts[0], "aie version major in %q", version)
	require.Equal(t, expectedMajor, parts[0], "aie version major")
}

func assertSARIF(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	require.NoError(t, err, "read sarif.json")
	require.NotEmpty(t, data, "sarif.json is empty")

	var doc struct {
		Version string            `json:"version"`
		Schema  string            `json:"$schema"`
		Runs    []json.RawMessage `json:"runs"`
	}
	require.NoError(t, json.Unmarshal(data, &doc), "parse sarif.json")
	require.NotEmpty(t, doc.Version, "sarif.version")
	require.NotEmpty(t, doc.Schema, "sarif.$schema")
	require.NotEmpty(t, doc.Runs, "sarif.runs")
}

func AssertPipelineArtifacts(t *testing.T, workDir, expectedMajor string) {
	t.Helper()

	meta := loadMeta(t, filepath.Join(workDir, "meta.json"))
	assertUUID(t, meta.ProjectID)
	assertUUID(t, meta.BranchID)
	assertUUID(t, meta.ScanID)
	assertVersionMajor(t, meta.AIEVersion, expectedMajor)
	assertSARIF(t, filepath.Join(workDir, "sarif.json"))
}
