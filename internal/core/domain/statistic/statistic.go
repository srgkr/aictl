package statistic

type Statistic struct {
	Total        int32  `json:"total"`
	High         int32  `json:"high"`
	Low          int32  `json:"low"`
	Medium       int32  `json:"medium"`
	Potential    int32  `json:"potential"`
	FilesScanned int32  `json:"filesScanned"`
	FilesTotal   int32  `json:"filesTotal"`
	PolicyState  string `json:"policyState"`
	ScanDuration string `json:"scanDuration"`
	UrlsScanned  int32  `json:"urlsScanned"`
	UrlsTotal    int32  `json:"urlsTotal"`
}
