package settings

import "github.com/google/uuid"

type PreferredAgentsSettings struct {
	PreferredAgents     []uuid.UUID `json:"preferredAgents"`
	PreferredAgentsOnly bool        `json:"preferredAgentsOnly"`
}
