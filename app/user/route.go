package user

import (
	"dev.balaganapathy/uni-server/constant"
	"dev.balaganapathy/uni-server/middleware"
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
}
