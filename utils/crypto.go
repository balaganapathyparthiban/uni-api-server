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
	"time"

	"dev.balaganapathy/uni-api-server/model"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/json"
	"github.com/go-jose/go-jose/v3/jwt"
)

type AccessTokenArgs struct {
	AccessToken string
	Payload     *model.AccessTokenPayload
	Jwks        string
	Kid         string
	Secret      string
}

func GenerateAccessToken(args *AccessTokenArgs) (string, error) {
	var keys jose.JSONWebKeySet
	json.NewDecoder(
		strings.NewReader(
			fmt.Sprintf(`{ "keys": [%s] }`, args.Jwks),
		),
	).Decode(&keys)

	if keys.Key(args.Kid) == nil {
		return "", fmt.Errorf("invalid kid")
	}

	key := keys.Key(args.Kid)[0]
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, &jose.SignerOptions{
		EmbedJWK: true,
	})
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	hasher := sha512.New()
	hasher.Write([]byte(args.Secret))
	hash512 := hex.EncodeToString(hasher.Sum(nil))

	bSecret := []byte(hash512[32:64])

	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.A256GCMKW,
		Key:       bSecret,
	}, (&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	if err != nil {
		return "", err
	}

	cl := jwt.Claims{
		Issuer:   "UNI",
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(90)),
	}

	accessToken, err := jwt.SignedAndEncrypted(signer, enc).Claims(cl).Claims(args.Payload).CompactSerialize()
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func VerifyAccessToken(args *AccessTokenArgs) (*model.AccessTokenPayload, error) {
	var keys jose.JSONWebKeySet
	json.NewDecoder(
		strings.NewReader(
			fmt.Sprintf(`{ "keys": [%s] }`, args.Jwks),
		),
	).Decode(&keys)

	if keys.Key(args.Kid) == nil {
		return nil, fmt.Errorf("invalid kid")
	}

	key := keys.Key(args.Kid)[0]
	hasher := sha512.New()
	hasher.Write([]byte(args.Secret))
	hash512 := hex.EncodeToString(hasher.Sum(nil))
	bSecretKey := []byte(hash512[32:64])

	token, err := jwt.ParseSignedAndEncrypted(args.AccessToken)
	if err != nil {
		return nil, err
	}

	nested, err := token.Decrypt(bSecretKey)
	if err != nil {
		return nil, err
	}

	payload := &model.AccessTokenPayload{}
	if err := nested.Claims(key, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func Encrypt(data string, key string) string {
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

	cipherText := Encrypt(data, key)

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

	msg, _ := hex.DecodeString(cipherTextlist[0])
	sig, _ := hex.DecodeString(cipherTextlist[1])

	isVerified := ed25519.Verify(pPublicKey.(ed25519.PublicKey), msg, sig)
	if !isVerified {
		return ""
	}

	data := Decrypt(cipherTextlist[0], key)

	return data
}
