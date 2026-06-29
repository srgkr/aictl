package config

import (
	"net/url"
	"strings"

	"github.com/POSIdev-community/aictl/internal/core/domain/validation"
)

type Uri struct {
	value string

	createByConstructor bool
}

func NewUri(value string) (Uri, error) {
	if value == "" {
		return Uri{}, validation.NewRequiredError("uri")
	}

	value = strings.TrimRight(value, "/")

	if _, err := url.ParseRequestURI(value); err != nil {
		return Uri{}, validation.NewInvalidError("uri")
	}

	return Uri{value: value, createByConstructor: true}, nil
}

func (u Uri) validate() error {
	if u.createByConstructor {
		return nil
	}

	return validation.NewInvalidError("uri")
}
