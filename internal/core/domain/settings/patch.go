package settings

import "github.com/google/uuid"

type ProjectSettingsPatch struct {
	Priority            *Priority
	PreferredAgents     *[]uuid.UUID
	PreferredAgentsOnly *bool
}

func (s *ScanSettings) Patch(p ProjectSettingsPatch) {
	if p.Priority != nil {
		s.Priority = *p.Priority
	}

	if p.PreferredAgents != nil {
		s.PreferredAgentsSettings.PreferredAgents = *p.PreferredAgents
	}

	if p.PreferredAgentsOnly != nil {
		s.PreferredAgentsSettings.PreferredAgentsOnly = *p.PreferredAgentsOnly
	}
}
