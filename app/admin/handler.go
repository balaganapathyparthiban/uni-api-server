package admin

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dev.balaganapathy/uni-api-server/config"
	"dev.balaganapathy/uni-api-server/constant"
	"dev.balaganapathy/uni-api-server/database/mongo"
	"dev.balaganapathy/uni-api-server/middleware"
	"dev.balaganapathy/uni-api-server/model"
	"dev.balaganapathy/uni-api-server/utils"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Google Login Handler
func GoogleLogin(c *fiber.Ctx) error {
	query := new(GoogleLoginQuery)

	// Validate Request Body
	c.QueryParser(query)
	if err := middleware.ValidateRequest(query); len(err) > 0 {
		// @Exception E1
		return c.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:       fiber.ErrBadRequest.Code,
				Message:    fiber.ErrBadRequest.Message,
				Validation: err,
				Reason:     "E1",
			},
		})
	}

	oAuth2Config := oauth2.Config{
		RedirectURL:  strings.Split(config.Getenv("GOOGLE_OAUTH_REDIRECT_URL"), ",")[1],
		ClientID:     config.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: config.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Getenv("GOOGLE_OAUTH_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}

	marshalState, _ := json.Marshal(&query)
	encState := utils.Encrypt(string(marshalState), config.Getenv("JWT_SECRET_KEY"))

	url := oAuth2Config.AuthCodeURL(encState)

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result: &fiber.Map{
			"url": url,
		},
	})
}

// Google Login Web Callback Handler
func GoogleLoginWebCallback(c *fiber.Ctx) error {
	state := c.Query("state")
	if state == "" {
		// @Exception E1
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", "http://localhost:5173/login", "E1 Invalid login credential"),
		)
	}

	decState := utils.Decrypt(state, config.Getenv("JWT_SECRET_KEY"))

	unmarshalState := new(GoogleLoginQuery)
	json.Unmarshal([]byte(decState), &unmarshalState)

	code := c.Query("code")

	oAuth2Config := oauth2.Config{
		RedirectURL:  strings.Split(config.Getenv("GOOGLE_OAUTH_REDIRECT_URL"), ",")[1],
		ClientID:     config.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: config.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Getenv("GOOGLE_OAUTH_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}
	token, err := oAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		// @Exception E2
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", "http://localhost:5173/login", "E2 Invalid login credential"),
		)
	}

	response, err := http.Get(
		fmt.Sprintf("%s?access_token=%s", config.Getenv("GOOGLE_OAUTH_USERINFO_ENDPOINT"), token.AccessToken),
	)
	if err != nil {
		// @Exception E3
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", "http://localhost:5173/login", "E3 Invalid login credential"),
		)
	}

	userData, err := io.ReadAll(response.Body)
	if err != nil {
		// @Exception E4
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", "http://localhost:5173/login", "E4 Invalid login credential"),
		)
	}

	var userInfo = &model.GoogleAuthResponse{}
	err = json.Unmarshal(userData, &userInfo)
	if err != nil {
		// @Exception E5
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", "http://localhost:5173/login", "E5 Invalid login credential"),
		)
	}

	fingerprintHash := sha512.New()
	fingerprintHash.Write([]byte(unmarshalState.FingerPrint))

	fmt.Println(userInfo)

	singleResult := mongo.Collection.Admins.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"email":  userInfo.Email,
			"status": model.Status.Active,
		},
		bson.M{
			"$set": bson.M{
				"googleId": userInfo.ID,
				"device": bson.M{
					"_id":      primitive.NewObjectID(),
					"name":     unmarshalState.DeviceName,
					"fcmToken": unmarshalState.FcmToken,
				},
				"updatedAt": time.Now().UTC(),
				"status":    model.Status.Active,
			},
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	fmt.Println(singleResult.Raw())
	fmt.Println(singleResult.Err())
	if singleResult.Err() != nil {
		// @Exception E6
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", "http://localhost:5173/login", "E6 Invalid login credential"),
		)
	}

	var updatedUser *model.User
	singleResult.Decode(&updatedUser)

	accessToken, err := utils.GenerateAccessToken(
		&utils.AccessTokenArgs{
			Payload: &model.AccessTokenPayload{
				Id:          updatedUser.ID.Hex(),
				GoogleId:    userInfo.ID,
				DeviceId:    updatedUser.Device.ID.Hex(),
				Type:        constant.TOKEN_TYPE_USER,
				FingerPrint: hex.EncodeToString(fingerprintHash.Sum(nil))[32:64],
			},
			Jwks:     config.Getenv("JWT_PRIVATE_KEY"),
			Kid:      config.Getenv("JWT_KID"),
			Secret:   config.Getenv("JWT_SECRET_KEY"),
			ExpiryAt: jwt.NewNumericDate(time.Now().UTC().Add(30 * time.Minute)),
		},
	)
	if err != nil {
		// @Exception E7
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", "http://localhost:5173/login", "E7 Invalid login credential"),
		)
	}

	return c.Status(308).Redirect(
		fmt.Sprintf("%s?data=%s", "http://localhost:5173/login", accessToken),
	)
}
