package gitignore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	ignore "github.com/denormal/go-gitignore"
)

type Exclusions struct {
	Patterns  []string
	FromFiles []string
}

type Matcher struct {
	ignoring ignore.GitIgnore
}

func NewMatcher(exclusions Exclusions) (*Matcher, error) {
	reader, err := collectReader(exclusions)
	if err != nil {
		return nil, err
	}

	return newMatcher(reader)
}

func collectReader(exclusions Exclusions) (io.Reader, error) {
	if len(exclusions.Patterns) == 0 && len(exclusions.FromFiles) == 0 {
		return nil, nil
	}

	readers := make([]io.Reader, 0, len(exclusions.Patterns)*2+len(exclusions.FromFiles)*2)

	for _, pattern := range exclusions.Patterns {
		readers = append(readers, strings.NewReader(pattern), strings.NewReader("\n"))
	}

	for _, path := range exclusions.FromFiles {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read exclude file %q: %w", path, err)
		}

		readers = append(readers, strings.NewReader(string(content)), strings.NewReader("\n"))
	}

	switch len(readers) {
	case 0:
		return nil, nil
	case 1:
		return readers[0], nil
	default:
		return io.MultiReader(readers...), nil
	}
}

func newMatcher(reader io.Reader) (*Matcher, error) {
	if reader == nil {
		return &Matcher{}, nil
	}

	var parseError error

	matcher := &Matcher{
		ignoring: ignore.New(reader, ".", func(e ignore.Error) bool {
			parseError = fmt.Errorf(
				"parse ignore rules failed at line %d column %d: %w",
				e.Position().Line,
				e.Position().Column,
				e,
			)

			return false
		}),
	}

	if parseError != nil {
		return nil, parseError
	}

	return matcher, nil
}

func (m *Matcher) Match(relPath string, isDir bool) bool {
	if m == nil || m.ignoring == nil {
		return false
	}

	path := filepath.ToSlash(relPath)
	if m.isIgnored(path, isDir) {
		return true
	}

	if !isDir {
		for dir := filepath.Dir(path); dir != "." && dir != ""; dir = filepath.Dir(dir) {
			if m.isIgnored(dir, true) {
				return true
			}
		}
	}

	return false
}

func (m *Matcher) isIgnored(path string, isDir bool) bool {
	match := m.ignoring.Relative(path, isDir)

	return match != nil && match.Ignore()
}
