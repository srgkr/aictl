package utils

import (
	"fmt"
	"io"
	"os"

	"github.com/POSIdev-community/aictl/internal/core/domain/validation"
	"github.com/POSIdev-community/aictl/internal/core/domain/version"
)

func RequireProjectScanSettings(serverVersion version.Version) error {
	minVersion, err := version.NewVersion("6.0.0")
	if err != nil {
		return fmt.Errorf("parse min version: %w", err)
	}

	if serverVersion.Less(minVersion) {
		return validation.NewError("priority and preferred agents settings are not supported on server version 5.4")
	}

	return nil
}

func CopyFileToPath(srcFile io.ReadCloser, fullDestPath string) error {
	destFile, err := os.Create(fullDestPath)
	if err != nil {
		return fmt.Errorf("create target file: %v", err)
	}

	defer func(destFile *os.File) {
		err := destFile.Close()
		if err != nil {
			// TODO log it
		}
	}(destFile)

	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return fmt.Errorf("copy file: %v", err)
	}

	return nil
}
