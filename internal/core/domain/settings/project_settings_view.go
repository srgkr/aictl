package settings

import "github.com/google/uuid"

type ProjectSettingsView struct {
	Priority            Priority    `json:"priority"`
	PreferredAgents     []uuid.UUID `json:"preferredAgents"`
	PreferredAgentsOnly bool        `json:"preferredAgentsOnly"`
}

func (s *ScanSettings) ProjectSettingsView() ProjectSettingsView {
	agents := s.PreferredAgentsSettings.PreferredAgents
	if agents == nil {
		agents = []uuid.UUID{}
	}

	return ProjectSettingsView{
		Priority:            s.Priority,
		PreferredAgents:     agents,
		PreferredAgentsOnly: s.PreferredAgentsSettings.PreferredAgentsOnly,
	}
}
