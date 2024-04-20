package main

import (
	"strings"

	"dev.balaganapathy/uni-server/app/auth"
	"dev.balaganapathy/uni-server/app/user"
	"dev.balaganapathy/uni-server/app/ws"
	"dev.balaganapathy/uni-server/config"
	"dev.balaganapathy/uni-server/constant"
	"dev.balaganapathy/uni-server/database/memcached"
	"dev.balaganapathy/uni-server/database/mongo"
	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
)

func main() {
	// Init Config
	config.Init()

	// Connect To Database
	mongo.ConnectMongoDB()

	// Connect Memcached
	memcached.ConnectMemcached()

	// Init Fiber
	app := fiber.New(fiber.Config{
		BodyLimit:         2 * 1024 * 1024,
		JSONEncoder:       json.Marshal,
		JSONDecoder:       json.Unmarshal,
		ReduceMemoryUsage: true,
	})

	/* Middlewares */

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

	/* Middlewares */

	/* ROUTES */

	// Health Check API
	app.Get("/healthcheck", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// API Group
	api := app.Group("/api")

	// Auth Routes
	auth.SetupAuthRoute(api)

	// User Routes
	user.SetupUserRoute(api)

	// Web Socket Routes
	ws.SetupWebSocketRoute(api)

	/* ROUTES */

	// APP Listen
	app.Listen(":3000")
}

func setupMiddlewares(app *fiber.App) {

}

func setupRoutes(app *fiber.App) {

}
