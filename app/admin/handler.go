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
	mongodriver "go.mongodb.org/mongo-driver/mongo"
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
			fmt.Sprintf("%s?error=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), "E1 Invalid login credential"),
		)
	}

	decState := utils.Decrypt(state, config.Getenv("JWT_SECRET_KEY"))

	unmarshalState := new(GoogleLoginQuery)
	json.Unmarshal([]byte(decState), &unmarshalState)

	code := c.Query("code")

	oAuth2Config := oauth2.Config{
		RedirectURL:  config.Getenv("GOOGLE_OAUTH_REDIRECT_URL_ADMIN"),
		ClientID:     config.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: config.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       strings.Split(config.Getenv("GOOGLE_OAUTH_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}
	token, err := oAuth2Config.Exchange(context.Background(), code)
	if err != nil {
		// @Exception E2
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), "E2 Invalid login credential"),
		)
	}

	response, err := http.Get(
		fmt.Sprintf("%s?access_token=%s", config.Getenv("GOOGLE_OAUTH_USERINFO_ENDPOINT"), token.AccessToken),
	)
	if err != nil {
		// @Exception E3
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), "E3 Invalid login credential"),
		)
	}

	userData, err := io.ReadAll(response.Body)
	if err != nil {
		// @Exception E4
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), "E4 Invalid login credential"),
		)
	}

	var userInfo = &model.GoogleAuthResponse{}
	err = json.Unmarshal(userData, &userInfo)
	if err != nil {
		// @Exception E5
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), "E5 Invalid login credential"),
		)
	}

	fingerprintHash := sha512.New()
	fingerprintHash.Write([]byte(unmarshalState.FingerPrint))

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
	if singleResult.Err() != nil {
		// @Exception E6
		return c.Status(308).Redirect(
			fmt.Sprintf("%s?error=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), "E6 Invalid login credential"),
		)
	}

	var updatedAdmin *model.Admin
	singleResult.Decode(&updatedAdmin)

	accessToken, err := utils.GenerateAccessToken(
		&utils.AccessTokenArgs{
			Payload: &model.AccessTokenPayload{
				Id:          updatedAdmin.ID.Hex(),
				GoogleId:    userInfo.ID,
				DeviceId:    updatedAdmin.Device.ID.Hex(),
				Type:        updatedAdmin.Type,
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
			fmt.Sprintf("%s?error=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), "E7 Invalid login credential"),
		)
	}

	return c.Status(308).Redirect(
		fmt.Sprintf("%s?data=%s", config.Getenv("ADMIN_APP_OAUTH_REDIRECT_URL"), accessToken),
	)
}

// Get Admin List
func GetAdminList(c *fiber.Ctx) error {
	query := new(GetAdminListQuery)

	c.QueryParser(query)

	accessTokenPayload := c.Locals(constant.TOKEN_PAYLOAD).(*model.AccessTokenPayload)
	userId, _ := primitive.ObjectIDFromHex(accessTokenPayload.Id)

	subAdminsCursor, err := mongo.Collection.Admins.Find(
		context.Background(),
		bson.M{
			"$or": bson.A{
				bson.M{"_id": userId},
				bson.M{"type": constant.TOKEN_TYPE_SUBADMIN},
			},
		},
		options.Find().SetSkip((int64(query.Page)-1)*int64(query.Limit)),
		options.Find().SetLimit(int64(query.Limit)),
	)
	if err != nil {
		// @Exception E1
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E1", err.Error()),
			},
		})
	}

	var subAdmins []model.Admin
	err = subAdminsCursor.All(context.Background(), &subAdmins)
	if err != nil {
		// @Exception E2
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E2", err.Error()),
			},
		})
	}

	return c.Status(fiber.StatusOK).JSON(subAdmins)
}

// Get Settings
func GetSettingList(c *fiber.Ctx) error {
	query := new(GetSettingListQuery)

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

	settingsCursorChan := make(chan *mongodriver.Cursor)
	settingsCursorErrChan := make(chan error)
	settingsCountChan := make(chan int64)

	go func() {
		filter := bson.M{
			"type": query.Type,
		}

		if query.SearchKey != "" && query.SearchValue != "" {
			filter[query.SearchKey] = bson.M{
				"$regex":   query.SearchValue,
				"$options": "i",
			}
		}

		if query.Status != "" {
			filter["status"] = query.Status
		}

		recordCount, _ := mongo.Collection.Settings.CountDocuments(context.Background(), filter)
		settingsCountChan <- recordCount
	}()

	go func() {
		filter := bson.M{
			"type": query.Type,
		}

		if query.SearchKey != "" && query.SearchValue != "" {
			filter[query.SearchKey] = bson.M{
				"$regex":   query.SearchValue,
				"$options": "i",
			}
		}

		if query.Status != "" {
			filter["status"] = query.Status
		}

		records, recordsErr := mongo.Collection.Settings.Find(
			context.Background(),
			filter,
			options.Find().SetSkip((int64(query.Page)-1)*int64(query.Limit)),
			options.Find().SetLimit(int64(query.Limit)),
		)
		settingsCursorChan <- records
		settingsCursorErrChan <- recordsErr
	}()

	settingsCount := <-settingsCountChan
	settingsCursor := <-settingsCursorChan
	settingsCursorErr := <-settingsCursorErrChan

	if settingsCursorErr != nil {
		// @Exception E2
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E2", settingsCursorErr.Error()),
			},
		})
	}

	var settings []model.Setting
	err := settingsCursor.All(context.Background(), &settings)
	if err != nil {
		// @Exception E3
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E3", err.Error()),
			},
		})
	}

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result: &fiber.Map{
			"list":  &settings,
			"count": settingsCount,
		},
	})
}

// Update Setting
func UpdateSetting(c *fiber.Ctx) error {
	body := new(UpdateSettingBody)

	// Validate Request Body
	c.BodyParser(body)
	if err := middleware.ValidateRequest(body); len(err) > 0 {
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

	updatedId := primitive.NewObjectID()
	updateData := bson.M{
		"type":   body.Type,
		"data":   body.Data,
		"status": body.Status,
	}
	if body.ID != nil && !body.ID.IsZero() {
		updatedId = *body.ID
		updateData["updatedAt"] = time.Now().UTC()
	} else {
		updateData["createdAt"] = time.Now().UTC()
	}

	updatedRecord := mongo.Collection.Settings.FindOneAndUpdate(
		context.Background(),
		bson.M{
			"_id": updatedId,
		},
		bson.M{
			"$set": updateData,
		},
		options.FindOneAndUpdate().SetUpsert(true),
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if updatedRecord.Err() != nil {
		// @Exception E2
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E2", updatedRecord.Err().Error()),
			},
		})
	}

	var record *model.Setting
	updatedRecord.Decode(&record)

	return c.Status(fiber.StatusOK).JSON(
		&model.DataResponse{
			Success: true,
			Result:  record,
		},
	)
}

// Delete Setting
func DeleteSetting(c *fiber.Ctx) error {
	body := new(DeleteSettingBody)

	// Validate Request Body
	c.BodyParser(body)
	if err := middleware.ValidateRequest(body); len(err) > 0 {
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

	deletedRecord, err := mongo.Collection.Settings.DeleteOne(
		context.Background(),
		bson.M{
			"_id":  body.ID,
			"type": body.Type,
		},
	)
	if err != nil {
		// @Exception E2
		return c.Status(fiber.StatusInternalServerError).JSON(model.ErrorResponse{
			Success: false,
			Error: &model.Error{
				Code:    fiber.ErrInternalServerError.Code,
				Message: fiber.ErrInternalServerError.Message,
				Reason:  fmt.Sprintf("%s %s", "E2", err.Error()),
			},
		})
	}

	return c.Status(fiber.StatusOK).JSON(&model.DataResponse{
		Success: true,
		Result:  &deletedRecord,
	})
}
