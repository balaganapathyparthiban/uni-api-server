package user

type UserConfig struct {
	Type string `json:"type" validate:"required,min=1,max=25"`
}

type GoogleLoginNativeCallbackBody struct {
	Code       string `json:"code" validate:"required,min=16,max=512"`
	DeviceType string `json:"deviceType" validate:"required,min=4,max=10"`
	DeviceName string `json:"deviceName" validate:"required,min=6,max=32"`
	FcmToken   string `json:"fcmToken" validate:"required,min=16,max=512"`
	Language   string `json:"language" validate:"required,min=2,max=3"`
}

type UserRegistrationBody struct {
	FullName    string `json:"fullName" validate:"required,min=6,max=25"`
	PhoneCode   string `json:"phoneCode" validate:"required,min=2,max=4"`
	PhoneNumber string `json:"phoneNumber" validate:"required,min=10,max=15"`
}
