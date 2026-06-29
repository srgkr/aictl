package queue

import "github.com/google/uuid"

type Item struct {
	Place  int
	OutOf  int
	ScanId uuid.UUID
}
