package apperror

import (
	"fmt"
	"testing"
)

func TestIsApiErrorCode(t *testing.T) {
	t.Parallel()

	apiErr := NewBadRequestApiErrorModelError("QUEUE_ITEM_ALREADY_ASSIGNED_TO_AGENT", nil)
	wrapped := fmt.Errorf("ai adapter get scan queue item: %w", apiErr)

	if !IsApiErrorCode(wrapped, "QUEUE_ITEM_ALREADY_ASSIGNED_TO_AGENT") {
		t.Fatal("expected wrapped API error to match by code")
	}

	if IsApiErrorCode(wrapped, "EMPTY_SCAN_RESULT") {
		t.Fatal("expected different API error code to not match")
	}

	if IsApiErrorCode(fmt.Errorf("other error"), "QUEUE_ITEM_ALREADY_ASSIGNED_TO_AGENT") {
		t.Fatal("expected non-API error to not match")
	}
}
