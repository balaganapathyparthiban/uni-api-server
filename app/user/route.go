package user

import (
	"dev.balaganapathy/uni-api-server/constant"
	"dev.balaganapathy/uni-api-server/middleware"
	"github.com/gofiber/fiber/v2"
)

func SetupUserRoute(router fiber.Router) {
	user := router.Group("/user")

	// Authorized Routes
	user.Get(
		"/info",
		middleware.AuthenticateRequest([]string{constant.TOKEN_TYPE_USER}),
		GetUserInfo,
	)
	user.Post(
		"/profile",
		middleware.AuthenticateRequest([]string{constant.TOKEN_TYPE_USER}),
		UpdateUserProfile,
	)
	user.Post(
		"/profile/registered",
		middleware.AuthenticateRequest([]string{constant.TOKEN_TYPE_USER}),
		updateUserProfileRegistered,
	)
}
