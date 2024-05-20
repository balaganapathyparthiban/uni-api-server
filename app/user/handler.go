package user

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
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Get Config
func GetConfig(c *fiber.Ctx) error {
	query := new(UserConfig)

	// Validate Request Body
	c.QueryParser(query)
	if err := middleware.ValidateRequest(query); len(err) > 0 {
		// @Exception E2
		return c.Status(fiber.StatusBadRequest).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:       fiber.ErrBadRequest.Code,
				Message:    fiber.ErrBadRequest.Message,
				Validation: err,
				Reason:     "E1",
			},
		})
	}

	recordCursor, err := mongo.Collection.Settings.Find(
		context.Background(),
		bson.M{
			"type":   query.Type,
			"status": model.Status.Active,
		},
	)
	if err != nil {
		// @Exception E2
		return c.Status(fiber.StatusInternalServerError).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  "E2",
			},
		})
	}

	var records []model.Setting
	recordCursor.All(context.Background(), &records)

	mapRecords := make([]interface{}, len(records))
	for i, record := range records {
		mapRecords[i] = record.Data
	}

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  &mapRecords,
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
		RedirectURL:  config.Getenv("GOOGLE_OAUTH_REDIRECT_URL_USER"),
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
				"updatedAt": time.Now().UTC(),
				"status":    model.Status.Active,
			},
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if singleResult.Err() != nil && singleResult.Err().Error() != "mongo: no documents in result" {
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
	if singleResult.Err() != nil && singleResult.Err().Error() == "mongo: no documents in result" {
		singleResult = mongo.Collection.Users.FindOneAndUpdate(
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
					"createdAt":    time.Now().UTC(),
					"updatedAt":    time.Now().UTC(),
					"status":       model.Status.Active,
				},
			},
			options.FindOneAndUpdate().SetUpsert(true),
			options.FindOneAndUpdate().SetReturnDocument(options.After),
		)
		if singleResult.Err() != nil {
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
			Jwks:   config.Getenv("JWT_PRIVATE_KEY"),
			Kid:    config.Getenv("JWT_KID"),
			Secret: config.Getenv("JWT_SECRET_KEY"),
		},
	)
	if err != nil {
		// @Exception E9
		return c.Status(fiber.StatusInternalServerError).JSON(&model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  "E9",
			},
		})
	}

	c.Set(constant.HEADER_X_EXPOSE_ACCESS_TOKEN, accessToken)
	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  utils.ConstructUserInfo(updatedUser),
	})
}

// User Info Handler
func GetUserProfile(c *fiber.Ctx) error {
	accessTokenPayload := c.Locals(constant.TOKEN_PAYLOAD).(*model.AccessTokenPayload)

	userID, _ := primitive.ObjectIDFromHex(accessTokenPayload.Id)
	deviceId, _ := primitive.ObjectIDFromHex(accessTokenPayload.DeviceId)

	// Find User by object id
	user := new(model.User)
	err := mongo.Collection.Users.FindOne(
		context.Background(),
		bson.M{
			"_id":        userID,
			"device._id": deviceId,
			"status":     bson.M{"$ne": model.Status.Blocked},
		},
		options.FindOne().SetProjection(bson.M{"otpHash": 0, "createdAt": 0, "updatedAt": 0}),
	).Decode(&user)
	if err != nil || user.ID == &primitive.NilObjectID {
		// @Exception E1
		return c.Status(fiber.StatusUnauthorized).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrUnauthorized.Code,
				Message: fiber.ErrUnauthorized.Message,
				Reason:  "E1",
			},
		})
	} else if user.Status == model.Status.Blocked {
		// @Exception E2
		return c.Status(fiber.StatusNotAcceptable).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrNotAcceptable.Code,
				Message: fiber.ErrNotAcceptable.Message,
				Reason:  "E2",
			},
		})
	}

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  utils.ConstructUserInfo(user),
	})
}

// User User profile Handler
func UpdateUserProfile(c *fiber.Ctx) error {
	accessTokenPayload := c.Locals(constant.TOKEN_PAYLOAD).(*model.AccessTokenPayload)

	userId, _ := primitive.ObjectIDFromHex(accessTokenPayload.Id)
	deviceId, _ := primitive.ObjectIDFromHex(accessTokenPayload.DeviceId)

	body := new(UserRegistrationBody)

	// Validate Request Body
	c.BodyParser(body)
	if err := middleware.ValidateRequest(body); len(err) > 0 {
		// @Exception E2
		return c.Status(fiber.StatusBadRequest).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:       fiber.ErrBadRequest.Code,
				Message:    fiber.ErrBadRequest.Message,
				Validation: err,
				Reason:     "E2",
			},
		})
	}

	singleResult := mongo.Collection.Users.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"_id":        userId,
			"device._id": deviceId,
			"status":     bson.M{"$ne": model.Status.Blocked},
		},
		bson.M{
			"$set": bson.M{
				"fullName":     body.FullName,
				"phone.code":   body.PhoneCode,
				"phone.number": body.PhoneNumber,
			},
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if singleResult.Err() != nil {
		// @Exception E3
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E3", singleResult.Err().Error()),
			},
		})
	}

	var updatedUser model.User
	singleResult.Decode(&updatedUser)

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  utils.ConstructUserInfo(&updatedUser),
	})
}

// Update User Profile Register Handler
func UpdateUserProfileRegister(c *fiber.Ctx) error {
	accessTokenPayload := c.Locals(constant.TOKEN_PAYLOAD).(*model.AccessTokenPayload)

	userId, _ := primitive.ObjectIDFromHex(accessTokenPayload.Id)
	deviceId, _ := primitive.ObjectIDFromHex(accessTokenPayload.DeviceId)

	singleResult := mongo.Collection.Users.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"_id":        userId,
			"device._id": deviceId,
			"status":     bson.M{"$ne": model.Status.Blocked},
		},
		bson.M{
			"$set": bson.M{
				"isRegistered": true,
			},
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if singleResult.Err() != nil {
		// @Exception E1
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E1", singleResult.Err().Error()),
			},
		})
	}

	var updatedUser model.User
	singleResult.Decode(&updatedUser)

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  utils.ConstructUserInfo(&updatedUser),
	})
}
