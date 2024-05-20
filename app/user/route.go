package user

import (
	"dev.balaganapathy/uni-api-server/constant"
	"dev.balaganapathy/uni-api-server/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupUserRoute(router fiber.Router) {
	user := router.Group("/user")

	// CONFIG
	user.Get(
		"/config",
		GetConfig,
	)

	// AUTH
	user.Post(
		"/google/login/native/callback",
		GoogleLoginNativeCallback,
	)

	// PROFILE
	user.Get(
		"/profile",
		middleware.AuthenticateRequest([]string{constant.TOKEN_TYPE_USER}),
		GetUserProfile,
	)
	user.Post(
		"/profile",
		middleware.AuthenticateRequest([]string{constant.TOKEN_TYPE_USER}),
		UpdateUserProfile,
	)
	user.Post(
		"/profile/register",
		middleware.AuthenticateRequest([]string{constant.TOKEN_TYPE_USER}),
		UpdateUserProfileRegister,
	)
}
