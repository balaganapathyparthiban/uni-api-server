package admin

type GoogleLoginQuery struct {
	FingerPrint string `json:"fingerPrint" validate:"required,min=6"`
	DeviceName  string `json:"deviceName" validate:"required,min=6"`
	FcmToken    string `json:"fcmToken" validate:"required,min=6"`
}
