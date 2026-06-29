//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadStandsExample(t *testing.T) {
	root, err := RepoRoot()
	require.NoError(t, err)

	path := filepath.Join(root, "tests", "e2e", "stands.example.yaml")
	stands, err := LoadStands(path)
	require.Error(t, err, "example config must use placeholder tokens")
	require.Nil(t, stands)
}
