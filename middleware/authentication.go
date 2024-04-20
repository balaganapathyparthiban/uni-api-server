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
			c.SendStatus(fiber.ErrUnauthorized.Code)
			return c.JSON(model.ErrorResponse{
				Success: false,
				Error: model.Error{
					Code:   fiber.ErrUnauthorized.Message,
					Reason: "Invalid access token",
				},
			})
		}

		payload, err := utils.VerifyAccessToken(accessToken)
		if err != nil || payload == nil || !slices.Contains(role, payload.Type) {
			c.SendStatus(fiber.ErrUnauthorized.Code)
			return c.JSON(model.ErrorResponse{
				Success: false,
				Error: model.Error{
					Code:   fiber.ErrUnauthorized.Message,
					Reason: "Invalid access token",
				},
			})
		}

		// @TODO Decrypt timestamp using fingerprint

		c.Locals(constant.TOKEN_PAYLOAD, payload)

		return c.Next()
	}
}
