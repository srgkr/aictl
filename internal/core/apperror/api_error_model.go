package apperror

import (
	"errors"
	"fmt"
	"strings"
)

type BadRequestApiErrorModelError struct {
	errorCode string
	details   map[string]*string
}

func (e *BadRequestApiErrorModelError) Error() string {
	result := make([]string, 0, len(e.details))
	for key, value := range e.details {
		str := fmt.Sprintf("%s: %s", key, *value)
		result = append(result, str)
	}

	if len(result) == 0 {
		return fmt.Sprintf("Bad request: '%s'", e.errorCode)
	}
	return fmt.Sprintf("Bad request: '%s'\n%s", e.errorCode, strings.Join(result, "\n"))
}

func NewBadRequestApiErrorModelError(errorCode string, details map[string]*string) *BadRequestApiErrorModelError {
	return &BadRequestApiErrorModelError{errorCode, details}
}

func (e *BadRequestApiErrorModelError) Code() string {
	return e.errorCode
}

func IsApiErrorCode(err error, code string) bool {
	var apiErr *BadRequestApiErrorModelError
	if !errors.As(err, &apiErr) {
		return false
	}

	return apiErr.Code() == code
}

type UnknownApiErrorModelError struct {
	statusCode int
	errorCode  string
	details    map[string]*string
}

func (e *UnknownApiErrorModelError) Error() string {
	result := make([]string, 0, len(e.details))
	for key, value := range e.details {
		str := fmt.Sprintf("%s: %s", key, *value)
		result = append(result, str)
	}

	if len(result) == 0 {
		return fmt.Sprintf("Unknown error. Status code: %d; %s", e.statusCode, e.errorCode)
	}
	return fmt.Sprintf("Unknown error. Status code: %d; %s\n%s", e.statusCode, e.errorCode, strings.Join(result, "\n"))
}

func NewUnknownApiErrorModelError(statusCode int, errorCode string, details map[string]*string) *UnknownApiErrorModelError {
	return &UnknownApiErrorModelError{
		statusCode,
		errorCode,
		details,
	}
}

func CheckApiErrorModel(statusCode int, errorCode string, details map[string]*string) error {
	switch {
	case statusCode < 400:
		return nil
	case statusCode == 400:
		return NewBadRequestApiErrorModelError(errorCode, details)
	case statusCode == 401:
		return NewAuthenticationError()
	case statusCode == 403:
		return NewAuthorizationError()
	case statusCode == 404:
		return NewNotFoundError(errorCode)
	default:
		return NewUnknownApiErrorModelError(statusCode, errorCode, details)
	}
}
