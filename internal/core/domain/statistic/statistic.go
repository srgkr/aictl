package statistic

type Statistic struct {
	Total     int32 `json:"total"`
	High      int32 `json:"high"`
	Low       int32 `json:"low"`
	Medium    int32 `json:"medium"`
	Potential int32 `json:"potential"`
}
