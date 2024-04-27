package middleware

import (
	"slices"

	"dev.balaganapathy/uni-server/constant"
	"dev.balaganapathy/uni-server/model"
	"dev.balaganapathy/uni-server/utils"
	"github.com/gofiber/fiber/v2"
)

// Authenticate The Request URL With Access Token
func AuthenticateRequest(role []string) func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		accessToken := c.Get(constant.HEADER_X_ACCESS_TOKEN)
		timeStamp := c.Get(constant.HEADER_X_TIME_STAMP)

		if accessToken == "" || timeStamp == "" {
			// @Token Exception TE1
			return c.Status(fiber.StatusUnauthorized).JSON(model.ErrorResponse{
				Success: false,
				Error: &model.Error{
					Code:    fiber.ErrUnauthorized.Code,
					Message: fiber.ErrUnauthorized.Message,
					Reason:  "TE1",
				},
			})
		}

		payload, err := utils.VerifyAccessToken(accessToken)
		if err != nil || payload == nil || !slices.Contains(role, payload.Type) {
			// @Token Exception TE2
			return c.Status(fiber.StatusUnauthorized).JSON(model.ErrorResponse{
				Success: false,
				Error: &model.Error{
					Code:    fiber.ErrUnauthorized.Code,
					Message: fiber.ErrUnauthorized.Message,
					Reason:  "TE2",
				},
			})
		}

		// @TODO Decrypt timestamp using fingerprint

		c.Locals(constant.TOKEN_PAYLOAD, payload)

		return c.Next()
	}
}
