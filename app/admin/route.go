package admin

import (
	"dev.balaganapathy/uni-api-server/constant"
	"dev.balaganapathy/uni-api-server/middleware"
	"github.com/gofiber/fiber/v2"
)

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

	// ADMIN
	admin.Get(
		"/subadmin/list",
		middleware.AuthenticateRequest(
			[]string{
				constant.TOKEN_TYPE_ADMIN,
				constant.TOKEN_TYPE_SUBADMIN,
			},
		),
		GetAdminList,
	)

	// SETTINGS
	admin.Get(
		"/settings/list",
		middleware.AuthenticateRequest(
			[]string{
				constant.TOKEN_TYPE_ADMIN,
				constant.TOKEN_TYPE_SUBADMIN,
			},
		),
		GetSettingList,
	)

	admin.Post(
		"/settings/update",
		middleware.AuthenticateRequest(
			[]string{
				constant.TOKEN_TYPE_ADMIN,
				constant.TOKEN_TYPE_SUBADMIN,
			},
		),
		UpdateSetting,
	)

	admin.Post(
		"/settings/delete",
		middleware.AuthenticateRequest(
			[]string{
				constant.TOKEN_TYPE_ADMIN,
				constant.TOKEN_TYPE_SUBADMIN,
			},
		),
		DeleteSetting,
	)
}
