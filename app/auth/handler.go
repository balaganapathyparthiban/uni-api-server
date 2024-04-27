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

// Google Login Handler
func GoogleLogin(c *fiber.Ctx) error {
	oAuth2Config := oauth2.Config{
		RedirectURL:  config.Getenv("GOOGLE_OAUTH_REDIRECT_URL"),
		ClientID:     config.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: config.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Getenv("GOOGLE_OAUTH_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}
	url := oAuth2Config.AuthCodeURL("unistate")

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
	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  &userData,
	})
}

// Google Login Native Callback Handler
func GoogleLoginNativeCallback(c *fiber.Ctx) error {
	fingerprint := c.GetReqHeaders()[constant.HEADER_X_FINGER_PRINT]
	if fingerprint == nil || (len(fingerprint) > 0 && fingerprint[0] == "") {
		// @Exception E1
		return c.Status(fiber.StatusBadRequest).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrBadRequest.Code,
				Message: fiber.ErrBadRequest.Message,
				Reason:  "E1",
			},
		})
	}

	body := new(GoogleLoginNativeCallbackBody)

	// Validate Request Body
	c.BodyParser(body)
	if err := middleware.ValidateRequest(body); len(err) > 0 {
		// @Exception E2
		return c.Status(fiber.StatusBadRequest).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:       fiber.ErrBadRequest.Code,
				Message:    fiber.ErrBadRequest.Message,
				Validation: err,
				Reason:     "E2",
			},
		})
	}

	if body.DeviceType != "android" || body.DeviceType == "ios" {
		// @Exception E3
		return c.Status(fiber.StatusUnauthorized).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrUnauthorized.Code,
				Message: fiber.ErrUnauthorized.Message,
				Reason:  "E3",
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
		// @Exception E4
		return c.Status(fiber.StatusUnauthorized).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrUnauthorized.Code,
				Message: fiber.ErrUnauthorized.Message,
				Reason:  "E4",
			},
		})
	}

	response, err := http.Get(
		fmt.Sprintf("%s?access_token=%s", config.Getenv("GOOGLE_OAUTH_USERINFO_ENDPOINT"), token.AccessToken),
	)
	if err != nil {
		// @Exception E5
		return c.Status(fiber.StatusUnauthorized).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrUnauthorized.Code,
				Message: fiber.ErrUnauthorized.Message,
				Reason:  "E5",
			},
		})
	}

	userData, err := io.ReadAll(response.Body)
	if err != nil {
		// @Exception E6
		return c.Status(fiber.StatusInternalServerError).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  "E6",
			},
		})
	}

	var userInfo = &model.GoogleAuthResponse{}
	err = json.Unmarshal(userData, &userInfo)
	if err != nil {
		// @Exception E7
		return c.Status(fiber.StatusInternalServerError).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  "E7",
			},
		})
	}

	fingerprintHash := sha512.New()
	fingerprintHash.Write([]byte(fingerprint[0]))

	singleResult := mongo.Collection.Users.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"googleId": userInfo.ID,
			"email":    userInfo.Email,
		},
		bson.M{
			"$set": bson.M{
				"device": bson.M{
					"_id":      primitive.NewObjectID(),
					"name":     body.DeviceName,
					"fcmToken": body.FcmToken,
				},
				"isRegistered": false,
				"language":     body.Language,
				"updatedAt":    time.Now().UTC(),
				"status":       model.Status.Active,
			},
		},
		options.FindOneAndUpdate().SetUpsert(true),
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if singleResult.Err() != nil {
		// @Exception E7
		return c.Status(fiber.StatusInternalServerError).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  "E7",
			},
		})
	}

	var updatedUser *model.User
	singleResult.Decode(&updatedUser)

	fmt.Printf("Device ID %v \n", updatedUser.Device.ID)

	accessToken, err := utils.GenerateAccessToken(&model.AccessTokenPayload{
		Id:          updatedUser.ID.Hex(),
		GoogleId:    userInfo.ID,
		DeviceId:    updatedUser.Device.ID.Hex(),
		Type:        constant.TOKEN_TYPE_USER,
		FingerPrint: hex.EncodeToString(fingerprintHash.Sum(nil))[32:64],
	})
	if err != nil {
		// @Exception E8
		return c.Status(fiber.StatusInternalServerError).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  "E8",
			},
		})
	}

	fmt.Printf("%v token", accessToken)

	c.Set(constant.HEADER_X_EXPOSE_ACCESS_TOKEN, accessToken)
	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  utils.ConstructUserInfo(updatedUser),
	})
}

// App Info Handler
func AppInfo(c *fiber.Ctx) error {
	jsonData := make(map[string]interface{})
	json.Unmarshal([]byte(`{
			"languages": [
				{"code": "en", "name": "English"},
				{"code": "ta", "name": "தமிழ்"},
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
				{"code": "te", "name": "తెలుగు"},
				{"code": "ur", "name": "اردو"}
		]
		}`), &jsonData)

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  &jsonData,
	})
}
