package model

var SettingType = &struct {
	SettingTypeFlagIcon   string
	SettingTypeValidation string
	SettingTypeConfig     string
}{
	SettingTypeFlagIcon:   "FLAG_ICON",
	SettingTypeValidation: "VALIDATION",
	SettingTypeConfig:     "CONFIG",
}

type Setting struct {
	Type string
	Data interface{}
}
