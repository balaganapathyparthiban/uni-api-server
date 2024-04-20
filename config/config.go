package config

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/derpen/fastergoding"
	"github.com/joho/godotenv"
)

/* Init Method */
func Init() {
	/* Handle HMR */
	var isHMR bool

	/* Check --hrm is passed or not */
	flag.BoolVar(&isHMR, "hmr", false, "Pass --dev to enable fastergoding.")
	flag.Parse()

	if isHMR {
		/* Run with HMR */
		fastergoding.Run()
	}

	/* Handle Ctrl+C */
	c := make(chan os.Signal, 1)

	/* Signal Notify When Interupt */
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	/* Go Routine Exit App When Signal Notify */
	go func() {
		<-c
		fmt.Println("[INFO][SIGNAL][CTRL+C] App stop running.")
		os.Exit(1)
	}()
}

/* Get Env Method */
func Getenv(key string) string {
	// load .env file
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Print("[ERROR][ENV][Getenv] Error loading .env file")
	}
	return os.Getenv(key)
}
