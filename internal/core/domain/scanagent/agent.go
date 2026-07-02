package scanagent

import "github.com/google/uuid"

type ScanAgent struct {
	Id              uuid.UUID
	Name            string
	Status          string
	Version         string
	OperatingSystem string
	Disabled        bool
	Stuck           bool
}
