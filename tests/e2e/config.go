//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigRelPath = "tests/e2e/stands.local.yaml"
	standOrder54         = "5.4"
	standOrder60         = "6.0"
)

var standOrder = []string{standOrder54, standOrder60}

type Stand struct {
	URL          string `yaml:"url"`
	Token        string `yaml:"token"`
	VersionMajor string `yaml:"version_major"`
}

type standsFile struct {
	Stands  map[string]Stand `yaml:"stands"`
	TLSSkip bool             `yaml:"tls_skip"`
}

func RepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}

	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found from %q", wd)
		}
		dir = parent
	}
}

func ConfigPath() (string, error) {
	if path := os.Getenv("AICTL_E2E_CONFIG"); path != "" {
		return path, nil
	}

	root, err := RepoRoot()
	if err != nil {
		return "", err
	}

	return filepath.Join(root, defaultConfigRelPath), nil
}

func LoadStands(path string) (map[string]Stand, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg standsFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	if len(cfg.Stands) == 0 {
		return nil, fmt.Errorf("config %q: no stands defined", path)
	}

	for name, stand := range cfg.Stands {
		if strings.TrimSpace(stand.URL) == "" {
			return nil, fmt.Errorf("stand %q: url is required", name)
		}
		if strings.TrimSpace(stand.Token) == "" || stand.Token == "<token>" {
			return nil, fmt.Errorf("stand %q: token is not configured", name)
		}
		if strings.TrimSpace(stand.VersionMajor) == "" {
			return nil, fmt.Errorf("stand %q: version_major is required", name)
		}
	}

	return cfg.Stands, nil
}

func OrderedStandNames(stands map[string]Stand) []string {
	names := make([]string, 0, len(standOrder))
	for _, name := range standOrder {
		if _, ok := stands[name]; ok {
			names = append(names, name)
		}
	}

	for name := range stands {
		found := false
		for _, ordered := range standOrder {
			if ordered == name {
				found = true
				break
			}
		}
		if !found {
			names = append(names, name)
		}
	}

	return names
}
