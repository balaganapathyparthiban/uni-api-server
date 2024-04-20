package auth

import (
	"github.com/gofiber/fiber/v2"
)

func SetupAuthRoute(router fiber.Router) {
	auth := router.Group("/auth")

	// UnAuthorized Routes
	auth.Get(
		"/google/login",
		GoogleAuthLogin,
	)

	auth.Get(
		"/google/login/web/callback",
		GoogleLoginWebCallback,
	)

	auth.Post(
		"/google/login/native/callback",
		GoogleLoginNativeCallback,
	)

	auth.Get("/app/info", GetAppInfo)
}
