package user

import (
	"context"

	"dev.balaganapathy/uni-server/constant"
	"dev.balaganapathy/uni-server/database/mongo"
	"dev.balaganapathy/uni-server/model"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// User Get Profile Handler
func GetUserInfo(c *fiber.Ctx) error {
	accessTokenPayload := c.Locals(constant.TOKEN_PAYLOAD).(*model.AccessTokenPayload)

	// Validate user object id
	userID, err := primitive.ObjectIDFromHex(accessTokenPayload.Id)
	if err != nil || userID == primitive.NilObjectID {
		c.SendStatus(fiber.ErrBadRequest.Code)
		return c.JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   fiber.ErrBadRequest.Message,
				Reason: "[ERROR] [VALIDATION] User account is not found",
			},
		})
	}

	// Find User by object id
	user := new(model.User)
	err = mongo.Collection.Users.FindOne(
		context.Background(),
		bson.M{
			"_id":    userID,
			"status": bson.M{"$ne": model.Status.Blocked},
		},
		options.FindOne().SetProjection(bson.M{"otpHash": 0, "createdAt": 0, "updatedAt": 0}),
	).Decode(&user)
	if err != nil || user.ID == &primitive.NilObjectID {
		c.SendStatus(fiber.ErrBadRequest.Code)
		return c.JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   fiber.ErrBadRequest.Message,
				Reason: "[ERROR] [VALIDATION] User account is not found",
			},
		})
	} else if user.Status == model.Status.Blocked {
		c.SendStatus(fiber.ErrUnauthorized.Code)
		return c.JSON(model.ErrorResponse{
			Success: false,
			Error: model.Error{
				Code:   fiber.ErrUnauthorized.Message,
				Reason: "[ERROR] [VALIDATION] Your account blocked by admin",
			},
		})
	}

	return c.JSON(model.DataResponse{
		Success: true,
		Result:  user,
	})
}
