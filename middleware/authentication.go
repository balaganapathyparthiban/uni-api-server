package middleware

import (
	"slices"

	"dev.balaganapathy/uni-api-server/config"
	"dev.balaganapathy/uni-api-server/constant"
	"dev.balaganapathy/uni-api-server/model"
	"dev.balaganapathy/uni-api-server/utils"
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

		payload, err := utils.VerifyAccessToken(&utils.AccessTokenArgs{
			AccessToken: accessToken,
			Jwks:        config.Getenv("JWT_PUBLIC_KEY"),
			Kid:         config.Getenv("JWT_KID"),
			Secret:      config.Getenv("JWT_SECRET_KEY"),
		})
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
