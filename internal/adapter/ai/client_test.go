package ai

import (
	"strings"
	"testing"

	client5x "github.com/POSIdev-community/aictl/internal/adapter/ai/5_x"
	client6x "github.com/POSIdev-community/aictl/internal/adapter/ai/6_x"
	"github.com/POSIdev-community/aictl/internal/core/domain/version"
)

var (
	_ ClientAi = (*client5x.ClientAI5x)(nil)
	_ ClientAi = (*client6x.ClientAI6x)(nil)
)

func TestValidateVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		version     string
		wantErr     bool
		errContains string
	}{
		{
			name:        "below minimum",
			version:     "4.9.9",
			wantErr:     true,
			errContains: "version less than 5.0.0",
		},
		{
			name:    "5x lower bound",
			version: "5.0.0",
		},
		{
			name:    "6x mid range",
			version: "6.5.0",
		},
		{
			name:        "at maximum",
			version:     "7.0.0",
			wantErr:     true,
			errContains: "version greater or equal to 7.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ver, err := version.NewVersion(tt.version)
			if err != nil {
				t.Fatalf("new version: %v", err)
			}

			err = validateVersion(ver)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestIsClient6xVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version string
		want    bool
	}{
		{version: "5.99.0", want: false},
		{version: "6.0.0", want: true},
		{version: "6.9.0", want: true},
		{version: "7.0.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			t.Parallel()

			ver, err := version.NewVersion(tt.version)
			if err != nil {
				t.Fatalf("new version: %v", err)
			}

			if got := isClient6xVersion(ver); got != tt.want {
				t.Fatalf("isClient6xVersion(%s) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}
