//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestBasePipeline(t *testing.T) {
	configPath, err := ConfigPath()
	if err != nil {
		t.Fatalf("config path: %v", err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Skip("e2e: create tests/e2e/stands.local.yaml (make e2e-config)")
	}

	stands, err := LoadStands(configPath)
	if err != nil {
		t.Skipf("e2e: %v", err)
	}

	root, err := RepoRoot()
	require.NoError(t, err)

	aictlBin := os.Getenv("AICTL_BIN")
	if aictlBin == "" {
		aictlBin = filepath.Join(root, "bin", "aictl")
	}
	if _, err := os.Stat(aictlBin); err != nil {
		t.Fatalf("aictl binary not found at %q: run make build-e2e", aictlBin)
	}

	e2eDir := filepath.Join(root, "tests", "e2e")
	scriptPath := filepath.Join(e2eDir, "run-pipeline.sh")
	fixturesDir := filepath.Join(e2eDir, "fixtures")

	for _, standName := range OrderedStandNames(stands) {
		stand := stands[standName]

		t.Run("AIE_"+standName, func(t *testing.T) {
			t.Parallel()

			workDir := t.TempDir()
			projectName := fmt.Sprintf("aictl-e2e-%s-%s", standName, uuid.NewString())

			cmd := exec.Command("bash", scriptPath, stand.URL, stand.Token, projectName)
			cmd.Dir = e2eDir
			cmd.Env = append(os.Environ(),
				"AICTL="+aictlBin,
				"FIXTURES_DIR="+fixturesDir,
				"WORK_DIR="+workDir,
			)

			out, runErr := cmd.CombinedOutput()
			require.NoError(t, runErr, "pipeline failed:\n%s", out)

			AssertPipelineArtifacts(t, workDir, stand.VersionMajor)
		})
	}
}
