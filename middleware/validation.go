package middleware

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// Validate Request Body, Query OR Params
func ValidateRequest(data interface{}) string {
	errMsgs := make([]string, 0)

	errs := validate.Struct(data)
	if errs != nil {
		for _, err := range errs.(validator.ValidationErrors) {
			errMsgs = append(errMsgs, fmt.Sprintf(
				"[%s]: '%v' | '%s %s'",
				err.Field(),
				err.Value(),
				err.Tag(),
				err.Param(),
			))
		}
	}

	return strings.Join(errMsgs, ", ")
}
