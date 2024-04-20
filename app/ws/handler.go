package ws

import (
	"bufio"
	"fmt"

	"github.com/goccy/go-json"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

var TripEventChan chan string = make(chan string)

func DriverEventStream(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	c.Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		for loop := true; loop; {
			message := <-TripEventChan
			messageMarshal, _ := json.Marshal(message)

			fmt.Fprintf(w, "data: %s\n\n", string(messageMarshal))

			err := w.Flush()
			if err != nil {
				loop = false
				return
			}
		}

	}))

	return nil
}
