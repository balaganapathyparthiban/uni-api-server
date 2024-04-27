package auth

type GoogleLoginNativeCallbackBody struct {
	Code       string `json:"code" validate:"required,min=6"`
	DeviceType string `json:"deviceType" validate:"required,min=2"`
	DeviceName string `json:"deviceName" validate:"required,min=6"`
	FcmToken   string `json:"fcmToken" validate:"required,min=6"`
	Language   string `json:"language" validate:"required,min=2"`
}
