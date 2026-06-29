package await

import (
	"testing"

	"github.com/POSIdev-community/aictl/internal/core/domain/queue"
	"github.com/google/uuid"
)

func TestAwaitQueueDisplay(t *testing.T) {
	t.Parallel()

	itemWithPlace := queue.Item{Place: 2, OutOf: 5, ScanId: uuid.New()}
	if itemWithPlace.OutOf <= 0 {
		t.Fatal("expected queue item with position")
	}

	itemWithoutPlace := queue.Item{ScanId: uuid.New()}
	if itemWithoutPlace.OutOf != 0 {
		t.Fatal("expected queue item without position when scan left queue")
	}
}
