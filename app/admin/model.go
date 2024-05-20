package admin

import "go.mongodb.org/mongo-driver/bson/primitive"

type GoogleLoginQuery struct {
	FingerPrint string `json:"fingerPrint" validate:"required,min=6"`
	DeviceName  string `json:"deviceName" validate:"required,min=6"`
	FcmToken    string `json:"fcmToken" validate:"required,min=6"`
}

type GetAdminListQuery struct {
	Page   int    `json:"page" validate:"required,min=1"`
	Limit  int    `json:"limit" validate:"required,min=10"`
	Search string `json:"search"`
	Sort   string `json:"sort"`
}

type GetSettingListQuery struct {
	Type        string `json:"type" validate:"required,min=1"`
	Page        int    `json:"page" validate:"required,min=1"`
	Limit       int    `json:"limit" validate:"required,min=10"`
	SearchKey   string `json:"searchKey"`
	SearchValue string `json:"searchValue"`
	Sort        string `json:"sort"`
	Status      string `json:"status"`
}

type UpdateSettingBody struct {
	ID     *primitive.ObjectID     `json:"id"`
	Type   string                  `json:"type" validate:"required,min=1"`
	Data   *map[string]interface{} `json:"data" validate:"required"`
	Status string                  `json:"status" validate:"required,min=1"`
}

type DeleteSettingBody struct {
	ID   *primitive.ObjectID `json:"id"`
	Type string              `json:"type" validate:"required,min=1"`
}
