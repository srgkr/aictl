package client

import "github.com/POSIdev-community/aictl/internal/core/domain/validation"

func ErrProjectScanSettingsNotSupported() error {
	return validation.NewError("priority and preferred agents settings are not supported on server version 5.4")
}
