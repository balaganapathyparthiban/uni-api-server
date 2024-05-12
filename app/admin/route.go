package admin

import "github.com/gofiber/fiber/v2"

func SetupAdminRoute(router fiber.Router) {
	admin := router.Group("/admin")

	// AUTH
	admin.Get(
		"/google/login",
		GoogleLogin,
	)

	admin.Get(
		"/google/login/web/callback",
		GoogleLoginWebCallback,
	)
}
