package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"dev.balaganapathy/uni-server/config"
	"dev.balaganapathy/uni-server/model"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

func GenerateSHA256(s string) string {
	h := sha256.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

func GenerateOTP(l int) (string, error) {
	seed := "9876543211234567890"
	byteSlice := make([]byte, l)

	for i := 0; i < l; i++ {
		max := big.NewInt(int64(len(seed)))
		num, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}

		byteSlice[i] = seed[num.Int64()]
	}

	return string(byteSlice), nil
}

func ParsePrivateKey(data string) *ecdsa.PrivateKey {
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

	if key, ok := key.(*ecdsa.PrivateKey); ok {
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

var privateKey = ParsePrivateKey(config.Getenv("JWT_PRIVATE_KEy"))
var signer = MakeSigner(jose.ES256, privateKey)
var secretKey = []byte(config.Getenv("JWT_SECRET_KEY"))[8:32]

func GenerateAccessToken(payload model.AccessTokenPayload) (string, error) {
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.A256GCMKW,
		Key:       secretKey,
	}, (&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		return "", err
	}

	cl := jwt.Claims{
		Issuer:   "UNI",
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
	}

	accessToken, err := jwt.SignedAndEncrypted(signer, enc).Claims(cl).Claims(payload).CompactSerialize()
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func VerifyAccessToken(accessToken string) (*model.AccessTokenPayload, error) {
	token, err := jwt.ParseSignedAndEncrypted(accessToken)
	if err != nil {
		return nil, err
	}

	nested, err := token.Decrypt(secretKey)
	if err != nil {
		return nil, err
	}

	payload := &model.AccessTokenPayload{}
	if err := nested.Claims(&privateKey.PublicKey, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}
