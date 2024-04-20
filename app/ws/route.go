package ws

import (
	"fmt"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

func SetupWebSocketRoute(router fiber.Router) {
	ws := router.Group("/ws")

	ws.Use("/", func(c *fiber.Ctx) error {
		// IsWebSocketUpgrade returns true if the client
		// requested upgrade to the WebSocket protocol.
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	})

	ws.Get("/:tripId", websocket.New(func(c *websocket.Conn) {
		// c.Locals is added to the *websocket.Conn
		fmt.Print(c.Locals("allowed"))  // true
		fmt.Print(c.Params("tripId"))   // 123
		fmt.Print(c.Query("v"))         // 1.0
		fmt.Print(c.Cookies("session")) // ""

		// websocket.Conn bindings https://pkg.go.dev/github.com/fasthttp/websocket?tab=doc#pkg-index
		var (
			mt  int
			msg []byte
			err error
		)
		for {
			if mt, msg, err = c.ReadMessage(); err != nil {
				fmt.Print("read:", err)
				break
			}
			fmt.Printf("mt: %v", mt)
			fmt.Printf("msg: %s", msg)

			if err = c.WriteMessage(mt, msg); err != nil {
				fmt.Print("write:", err)
				break
			}
		}
	}))
}
