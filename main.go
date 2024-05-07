package main

import (
	"strings"

	"dev.balaganapathy/uni-api-server/app/auth"
	"dev.balaganapathy/uni-api-server/app/user"
	"dev.balaganapathy/uni-api-server/app/ws"
	"dev.balaganapathy/uni-api-server/config"
	"dev.balaganapathy/uni-api-server/constant"
	"dev.balaganapathy/uni-api-server/database/memcached"
	"dev.balaganapathy/uni-api-server/database/mongo"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
)

func main() {
	/*############
	### CONFIG ###
	##############*/

	config.Init()

	return

	/*##############
	### DATABASE ###
	################*/

	mongo.ConnectMongoDB()

	/*###########
	### CACHE ###
	#############*/

	memcached.ConnectMemcached()

	/*################
	### FIBER INIT ###
	##################*/

	app := fiber.New(fiber.Config{
		BodyLimit:         2 * 1024 * 1024,
		JSONEncoder:       json.Marshal,
		JSONDecoder:       json.Unmarshal,
		ReduceMemoryUsage: true,
	})

	/*#################
	### MIDDLEWARES ###
	###################*/

	app.Use(cors.New(cors.Config{
		AllowOrigins: strings.Join(
			[]string{
				"*",
			},
			", ",
		),
		AllowMethods: strings.Join(
			[]string{
				"GET",
				"POST",
			},
			", ",
		),
		AllowHeaders: strings.Join(
			[]string{
				"Accept",
				"Accept-Encoding",
				"Content-Type",
				"Origin",
				constant.HEADER_X_FINGER_PRINT,
				constant.HEADER_X_ACCESS_TOKEN,
				constant.HEADER_X_TIME_STAMP,
			},
			", ",
		),
		ExposeHeaders: strings.Join(
			[]string{
				constant.HEADER_X_EXPOSE_ACCESS_TOKEN,
			},
			", ",
		),
	}))

	app.Use(helmet.New())

	/*##############
	### ROUTES #####
	################*/

	app.Get("/healthcheck", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	api := app.Group("/api")

	auth.SetupAuthRoute(api)

	user.SetupUserRoute(api)

	ws.SetupWebSocketRoute(api)

	/*###############
	### APP START ###
	#################*/

	app.Listen(":3000")
}
