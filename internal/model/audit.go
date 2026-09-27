package model

type Audit struct {
	User   string `json:"user"`
	Token  string `json:"token"`
	Mask   string `json:"masked"`
	Action string `json:"action"`
	OK     bool   `json:"ok"`
}
