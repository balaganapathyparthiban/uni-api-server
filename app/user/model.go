package user

type LoginSendOTPBody struct {
	IsoCode      string `json:"isoCode" validate:"required,min=2,max=4"`
	MobileNumber string `json:"mobileNumber" validate:"required"`
	LanguageCode string `json:"languageCode" validate:"required"`
}

type LoginVerifyOTPBody struct {
	IsoCode      string `json:"isoCode" validate:"required,min=2,max=4"`
	MobileNumber string `json:"mobileNumber" validate:"required"`
	Otp          string `json:"otp" validate:"required,min=6,max=6"`
}
