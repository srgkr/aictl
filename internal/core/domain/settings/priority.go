package settings

import (
	"fmt"
	"slices"

	"github.com/POSIdev-community/aictl/internal/core/domain/validation"
)

type Priority string

const (
	PriorityNone     Priority = "None"
	PriorityLow      Priority = "Low"
	PriorityMedium   Priority = "Medium"
	PriorityHigh     Priority = "High"
	PriorityCritical Priority = "Critical"
)

var validPriorities = []Priority{
	PriorityNone,
	PriorityLow,
	PriorityMedium,
	PriorityHigh,
	PriorityCritical,
}

func (p Priority) Validate() error {
	if p == "" {
		return nil
	}

	if !slices.Contains(validPriorities, p) {
		return validation.NewFieldError("priority", fmt.Sprintf("must be one of %v", validPriorities))
	}

	return nil
}

func ParsePriority(s string) (Priority, error) {
	p := Priority(s)
	if err := p.Validate(); err != nil {
		return "", err
	}

	return p, nil
}
