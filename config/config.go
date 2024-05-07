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

	/* Get Properties */
	_, publicKey, privateKey := getProperties()

	publicKeyDecrypted := utils.Decrypt(publicKey, Getenv("KEYVAULT_KEY"))
	privateKeyDecrypted := utils.Decrypt(privateKey, Getenv("KEYVAULT_KEY"))

	fmt.Println(publicKeyDecrypted)
	fmt.Println(privateKeyDecrypted)

	rvalue := utils.RSAEncrypt("test", publicKeyDecrypted, privateKeyDecrypted)
	fmt.Println(rvalue)

	rdvalue := utils.RSADecrypt(rvalue, publicKeyDecrypted, privateKeyDecrypted)
	fmt.Println(rdvalue)
}

func getProperties() (string, string, string) {
	urls := [3]string{
		fmt.Sprintf("%s/app.properties", Getenv("KEYVAULT_URL")),
		fmt.Sprintf("%s/keys/public.pem", Getenv("KEYVAULT_URL")),
		fmt.Sprintf("%s/keys/private.pem", Getenv("KEYVAULT_URL")),
	}

	properties := make(chan string)
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

			if strings.Contains(url, "app.properties") {
				properties <- value
			}
			if strings.Contains(url, "public.pem") {
				publicKey <- value
			}
			if strings.Contains(url, "private.pem") {
				privateKey <- value
			}
		}(url)
	}

	return <-properties, <-publicKey, <-privateKey
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
