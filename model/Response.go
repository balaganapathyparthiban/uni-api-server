package model

import "github.com/go-jose/go-jose/v3/jwt"

type DataResponse struct {
	Success bool        `json:"success"`
	Result  interface{} `json:"result"`
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   *Error `json:"error"`
}

type Error struct {
	Code       int      `json:"code"`
	Message    string   `json:"message"`
	Validation []string `json:"validation"`
	Reason     string   `json:"reason"`
}

type AccessTokenPayload struct {
	Id          string           `json:"id"`
	Type        string           `json:"type"`
	GoogleId    string           `json:"googleId"`
	DeviceId    string           `json:"deviceId"`
	FingerPrint string           `json:"fingerPrint"`
	Issuer      *string          `json:"iss"`
	IssuedAt    *jwt.NumericDate `json:"iat"`
}

type GoogleAuthResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
}
