package auth

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"dev.balaganapathy/uni-server/config"
	"dev.balaganapathy/uni-server/constant"
	"dev.balaganapathy/uni-server/database/mongo"
	"dev.balaganapathy/uni-server/middleware"
	"dev.balaganapathy/uni-server/model"
	"dev.balaganapathy/uni-server/utils"
	"github.com/go-jose/go-jose/v3/json"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Google Auth Login Handler
func GoogleAuthLogin(c *fiber.Ctx) error {
	oAuth2Config := oauth2.Config{
		RedirectURL:  config.Getenv("GOOGLE_OAUTH_REDIRECT_URL"),
		ClientID:     config.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: config.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Getenv("GOOGLE_OAUTH_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}
	url := oAuth2Config.AuthCodeURL("unistate")

	return c.Status(200).JSON(model.DataResponse{
		Success: true,
		Result: fiber.Map{
			"url": url,
		},
	})
}

// Google Auth Login Web Callback Handler
func GoogleLoginWebCallback(c *fiber.Ctx) error {
	state := c.Query("state")
	if state != "unistate" {
		// return c.Status(308).Redirect(
		// 	fmt.Sprintf("%s?error=%s", "uniuserapp://uniuserapp.io", "Invalid login credential"),
		// )
		return c.SendString("Error")
	}

	code := c.Query("code")

	oAuth2Config := oauth2.Config{
		RedirectURL:  config.Getenv("GOOGLE_OAUTH_REDIRECT_URL"),
		ClientID:     config.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: config.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Getenv("GOOGLE_OAUTH_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}
	token, err := oAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		return c.SendString("Error")
	}

	response, err := http.Get(
		fmt.Sprintf("%s?access_token=%s", config.Getenv("GOOGLE_OAUTH_USERINFO_ENDPOINT"), token.AccessToken),
	)
	if err != nil {
		return c.SendString("Error")
	}

	userData, err := io.ReadAll(response.Body)
	if err != nil {
		return c.SendString("Error")
	}

	// return c.Status(308).Redirect(
	// 	fmt.Sprintf("%s?data=%s", "uniuserapp://uniuserapp.io", code),
	// )
	return c.JSON(userData)
}

// Google Auth Login Native Callback Handler
func GoogleLoginNativeCallback(c *fiber.Ctx) error {
	fingerprint := c.GetReqHeaders()[constant.HEADER_X_FINGER_PRINT][0]
	if fingerprint == "" {
		return c.Status(401).JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   "INVALID_CREDENTIAL",
				Reason: "Invalid credential",
			},
		})
	}

	body := new(GoogleLoginNativeCallbackBody)

	// Validate Request Body
	c.BodyParser(body)
	if err := middleware.ValidateRequest(body); err != "" {
		c.SendStatus(fiber.ErrBadRequest.Code)
		return c.JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   fiber.ErrBadRequest.Message,
				Reason: err,
			},
		})
	}

	oAuth2Config := oauth2.Config{
		RedirectURL:  config.Getenv("GOOGLE_OAUTH_REDIRECT_URL"),
		ClientID:     config.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: config.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Getenv("GOOGLE_OAUTH_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}
	token, err := oAuth2Config.Exchange(context.Background(), body.Code)
	if err != nil {
		return c.Status(401).JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   "INVALID_CODE",
				Reason: "Invalid code",
			},
		})
	}

	response, err := http.Get(
		fmt.Sprintf("%s?access_token=%s", config.Getenv("GOOGLE_OAUTH_USERINFO_ENDPOINT"), token.AccessToken),
	)
	if err != nil {
		return c.Status(401).JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   "INVALID_TOKEN",
				Reason: "Invalid token",
			},
		})
	}

	userData, err := io.ReadAll(response.Body)
	if err != nil {
		return c.Status(500).JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   "FAILED_TO_PARSE_BODY",
				Reason: "Failed to parse body",
			},
		})
	}

	var userInfo = &model.GoogleAuthResponse{}
	err = json.Unmarshal(userData, &userInfo)
	if err != nil {
		return c.Status(500).JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   "FAILED_TO_UNMARSHALL_DATA",
				Reason: "Failed to unmarshall data",
			},
		})
	}

	fingerprintHash := sha512.New()
	fingerprintHash.Write([]byte(fingerprint))

	deviceId := primitive.NewObjectID()

	singleResult := mongo.Collection.Users.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"googleId": userInfo.ID,
			"email":    userInfo.Email,
		},
		bson.M{
			"$set": bson.M{
				"device": bson.M{
					"_id":      deviceId,
					"name":     body.DeviceName,
					"fcmToken": body.FcmToken,
				},
				"language":  body.Language,
				"updatedAt": time.Now().UTC(),
				"status":    model.Status.Active,
			},
		},
		options.FindOneAndUpdate().SetUpsert(true),
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if singleResult.Err() != nil {
		return c.Status(500).JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   "FAILED_TO_UPDATE_USER",
				Reason: "Failed to update user",
			},
		})
	}

	var updatedUser model.User
	singleResult.Decode(&updatedUser)

	accessToken, err := utils.GenerateAccessToken(model.AccessTokenPayload{
		Id:          updatedUser.ID.Hex(),
		Type:        constant.TOKEN_TYPE_USER,
		GoogleId:    userInfo.ID,
		DeviceId:    deviceId.Hex(),
		FingerPrint: hex.EncodeToString(fingerprintHash.Sum(nil))[32:64],
	})
	if err != nil {
		return c.Status(500).JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   "FAILED_TO_GENERATE_TOKEN",
				Reason: "Failed to generate token",
			},
		})
	}

	return c.Status(200).JSON(model.DataResponse{
		Success: true,
		Result: bson.M{
			"accessToken": accessToken,
		},
	})
}

// Get App Info Handler
func GetAppInfo(c *fiber.Ctx) error {
	jsonData := make(map[string]interface{})
	json.Unmarshal([]byte(`{
			"languages": [
				{"code": "en", "name": "English"},
				{"code": "as", "name": "অসমীয়া"},
				{"code": "bn", "name": "বাংলা"},
				{"code": "gu", "name": "ગુજરાતી"},
				{"code": "hi", "name": "हिन्दी"},
				{"code": "kn", "name": "ಕನ್ನಡ"},
				{"code": "ml", "name": "മലയാളം"},
				{"code": "mr", "name": "मराठी"},
				{"code": "or", "name": "ଓଡ଼ିଆ"},
				{"code": "pa", "name": "ਪੰਜਾਬੀ"},
				{"code": "sa", "name": "संस्कृतम्"},
				{"code": "ta", "name": "தமிழ்"},
				{"code": "te", "name": "తెలుగు"},
				{"code": "ur", "name": "اردو"}
		]
		}`), &jsonData)

	return c.Status(200).JSON(model.DataResponse{
		Success: true,
		Result:  jsonData,
	})
}
