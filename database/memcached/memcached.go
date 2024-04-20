package memcached

import (
	"fmt"

	"dev.balaganapathy/uni-server/config"
	"github.com/bradfitz/gomemcache/memcache"
)

var Client *memcache.Client

func ConnectMemcached() {
	Client = memcache.New(config.Getenv("MEMCACHED_URI"))

	err := Client.Ping()
	if err != nil {
		fmt.Println("[ERROR][CACHE][MEMCACHED]: ", err)
	} else {
		fmt.Println("[INFO][CACHE][MEMCACHED]: Memcached Connected Successfully")
	}
}
