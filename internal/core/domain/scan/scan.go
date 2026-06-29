package scan

import (
	"time"

	"github.com/google/uuid"
)

type Scan struct {
	Id         uuid.UUID
	SettingsId uuid.UUID
	ScanDate   time.Time
	ScanLabel  string
}

func NewScan(id, settingsId uuid.UUID, scanDate *time.Time, scanLabel *string) Scan {
	label := ""
	if scanLabel != nil {
		label = *scanLabel
	}

	date := time.Time{}
	if scanDate != nil {
		date = *scanDate
	}

	return Scan{
		Id:         id,
		SettingsId: settingsId,
		ScanDate:   date,
		ScanLabel:  label,
	}
}
