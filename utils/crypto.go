package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"dev.balaganapathy/uni-api-server/model"
	"github.com/go-jose/go-jose/v3"
)

func ParsePrivateKey(data string) *ed25519.PrivateKey {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		fmt.Printf("%v", "failed to decode PEM data")
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("%v", "failed to parse RSA key: "+err.Error())
		return nil
	}

	if key, ok := key.(*ed25519.PrivateKey); ok {
		return key
	}

	return nil
}

func MakeSigner(alg jose.SignatureAlgorithm, k interface{}) jose.Signer {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, nil)
	if err != nil {
		fmt.Printf("%v", "failed to create signer:"+err.Error())
		return nil
	}

	return sig
}

// var privateKey = ParsePrivateKey(config.Getenv("JWT_PRIVATE_KEy"))
// var signer = MakeSigner(jose.ED25519, privateKey)
// var secretKey = []byte(config.Getenv("JWT_SECRET_KEY"))[8:32]

func GenerateAccessToken(payload *model.AccessTokenPayload) (string, error) {
	fmt.Printf("Generate Access Token %v \n", payload.DeviceId)
	// enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
	// 	Algorithm: jose.A256GCMKW,
	// 	Key:       secretKey,
	// }, (&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	// if err != nil {
	// 	return "", err
	// }

	// cl := jwt.Claims{
	// 	Issuer:   "UNI",
	// 	IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
	// }

	// accessToken, err := jwt.SignedAndEncrypted(signer, enc).Claims(cl).Claims(payload).CompactSerialize()
	// if err != nil {
	// 	return "", err
	// }

	return "", nil
}

func VerifyAccessToken(accessToken string) (*model.AccessTokenPayload, error) {
	// token, err := jwt.ParseSignedAndEncrypted(accessToken)
	// if err != nil {
	// 	return nil, err
	// }

	// nested, err := token.Decrypt(secretKey)
	// if err != nil {
	// 	return nil, err
	// }

	// payload := &model.AccessTokenPayload{}
	// if err := nested.Claims(&privateKey.PublicKey, &payload); err != nil {
	// 	return nil, err
	// }
	// fmt.Printf("Verify Access Token %v \n", payload.DeviceId)

	return &model.AccessTokenPayload{}, nil
}

func EncryptGCM(data string, key string) string {
	hasher := sha512.New()
	hasher.Write([]byte(key))
	hash512 := hex.EncodeToString(hasher.Sum(nil))

	newKey := []byte(hash512[32:64])
	nonce := []byte(hash512[64:(64 + 12)])

	block, _ := aes.NewCipher(newKey)
	aesgcm, _ := cipher.NewGCMWithTagSize(block, 16)
	cipherText := aesgcm.Seal(nil, nonce, []byte(data), nil)

	return hex.EncodeToString(cipherText)
}

func Decrypt(cipherText string, key string) string {
	hasher := sha512.New()
	hasher.Write([]byte(key))
	hash512 := hex.EncodeToString(hasher.Sum(nil))

	newKey := []byte(hash512[32:64])
	nonce := []byte(hash512[64:(64 + 12)])

	block, _ := aes.NewCipher(newKey)
	aesgcm, _ := cipher.NewGCMWithTagSize(block, 16)
	dCipherText, _ := hex.DecodeString(cipherText)

	data, _ := aesgcm.Open(nil, nonce, dCipherText, nil)

	return string(data)
}

func RSAEncrypt(data string, publicKey string, privateKey string) string {
	hasher := sha512.New()
	hasher.Write(append([]byte(publicKey), []byte(privateKey)...))
	key := hex.EncodeToString(hasher.Sum(nil))

	cipherText := EncryptGCM(data, key)

	dPrivateKey, _ := pem.Decode([]byte(privateKey))
	pPrivateKey, _ := x509.ParsePKCS8PrivateKey(dPrivateKey.Bytes)

	signature := ed25519.Sign(pPrivateKey.(ed25519.PrivateKey), []byte(cipherText))

	return fmt.Sprintf("%s:%s", cipherText, hex.EncodeToString(signature))
}

func RSADecrypt(cipherText string, publicKey string, privateKey string) string {
	hasher := sha512.New()
	hasher.Write(append([]byte(publicKey), []byte(privateKey)...))
	key := hex.EncodeToString(hasher.Sum(nil))

	cipherTextlist := strings.Split(cipherText, ":")

	dPublicKey, _ := pem.Decode([]byte(publicKey))
	pPublicKey, _ := x509.ParsePKIXPublicKey(dPublicKey.Bytes)

	fmt.Println(string(pPublicKey.(ed25519.PublicKey)))

	isVerified := ed25519.Verify(pPublicKey.(ed25519.PublicKey), []byte(cipherTextlist[0]), []byte(cipherTextlist[1]))
	if !isVerified {
		return ""
	}

	data := Decrypt(cipherTextlist[0], key)

	return data
}
