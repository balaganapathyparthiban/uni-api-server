package user

import (
	"context"
	"fmt"

	"dev.balaganapathy/uni-api-server/constant"
	"dev.balaganapathy/uni-api-server/database/mongo"
	"dev.balaganapathy/uni-api-server/middleware"
	"dev.balaganapathy/uni-api-server/model"
	"dev.balaganapathy/uni-api-server/utils"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// User Info Handler
func GetUserInfo(c *fiber.Ctx) error {
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

// Update User Profile Registered Handler
func updateUserProfileRegistered(c *fiber.Ctx) error {
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
