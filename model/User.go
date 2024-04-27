package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           *primitive.ObjectID `bson:"_id" json:"_id,omitempty"`
	GoogleId     string              `bson:"googleId" json:"googleId,omitempty"`
	Email        string              `bson:"email,omitempty" json:"email,omitempty"`
	Avatar       string              `bson:"avatar,omitempty" json:"avatar,omitempty"`
	FullName     string              `bson:"fullName,omitempty" json:"fullName,omitempty"`
	Phone        *Phone              `bson:"phone,omitempty" json:"phone,omitempty"`
	Addressess   *[]Address          `bson:"addresses,omitempty" json:"addresses,omitempty"`
	Device       *Device             `bson:"device,omitempty" json:"device,omitempty"`
	IsRegistered bool                `bson:"isRegistered,omitempty" json:"isRegistered,omitempty"`
	Language     string              `bson:"language,omitempty" json:"language,omitempty"`
	CreatedAt    *time.Time          `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt    *time.Time          `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	Status       string              `bson:"status,omitempty" json:"status,omitempty"`
}
