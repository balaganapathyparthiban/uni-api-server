package user

type UserRegistrationBody struct {
	FullName    string `json:"fullName" validate:"required,min=6"`
	PhoneCode   string `json:"phoneCode" validate:"required,min=2"`
	PhoneNumber string `json:"phoneNumber" validate:"required,min=10"`
}
