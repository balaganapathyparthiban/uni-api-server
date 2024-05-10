package config

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"dev.balaganapathy/uni-api-server/utils"
	"github.com/derpen/fastergoding"
	"github.com/go-jose/go-jose/v3/json"
	"github.com/joho/godotenv"
)

var properties = make(map[string]string)

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

	// load .env file
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Print("[ERROR][ENV][Getenv] Error loading .env file")
		os.Exit(1)
	}

	/* Get Properties */
	urls := [3]string{
		fmt.Sprintf("%s/%s?v=1", Getenv("KEYVAULT_URL"), Getenv("APP_PROPERTIES_FILE")),
		fmt.Sprintf("%s/keys/%s?v=1", Getenv("KEYVAULT_URL"), Getenv("PUBLIC_KEY_FILE")),
		fmt.Sprintf("%s/keys/%s?v=1", Getenv("KEYVAULT_URL"), Getenv("PRIVATE_KEY_FILE")),
	}

	appProperties := make(chan string)
	publicKey := make(chan string)
	privateKey := make(chan string)

	for _, url := range urls {
		go func(url string) {
			var value string
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				fmt.Println("[ERROR][GET PROPERTIES] Error while constructing url.")
				value = ""
				return
			}
			req.Header.Set("Authorization", fmt.Sprintf("token %s", Getenv("KEYVAULT_TOKEN")))

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Println("[ERROR][GET PROPERTIES] Error fetching data from url.")
				value = ""
				return
			}
			defer resp.Body.Close()

			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("[ERROR][GET PROPERTIES] Error while parsing body.")
				value = ""
				return
			}
			value = string(bodyBytes)

			if strings.Contains(url, Getenv("APP_PROPERTIES_FILE")) {
				appProperties <- value
			}
			if strings.Contains(url, Getenv("PUBLIC_KEY_FILE")) {
				publicKey <- value
			}
			if strings.Contains(url, Getenv("PRIVATE_KEY_FILE")) {
				privateKey <- value
			}
		}(url)
	}

	dPublicKey := utils.Decrypt(<-publicKey, Getenv("KEYVAULT_KEY"))
	dPrivateKey := utils.Decrypt(<-privateKey, Getenv("KEYVAULT_KEY"))
	mProperties := utils.RSADecrypt(<-appProperties, dPublicKey, dPrivateKey)

	json.Unmarshal([]byte(mProperties), &properties)
}

/* Get Env Method */
func Getenv(key string) string {
	if os.Getenv(key) != "" {
		return os.Getenv(key)
	} else {
		return properties[key]
	}
}
