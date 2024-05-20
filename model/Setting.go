package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var SettingType = &struct {
	SettingTypeCountry     string
	SettingTypeValidation  string
	SettingTypeTranslation string
	SettingTypeLanguage    string
}{
	SettingTypeCountry:     "COUNTRY",
	SettingTypeValidation:  "VALIDATION",
	SettingTypeTranslation: "TRANSLATION",
	SettingTypeLanguage:    "LANGUAGE",
}

type Setting struct {
	ID        *primitive.ObjectID     `bson:"_id" json:"_id,omitempty"`
	Type      string                  `bson:"type" json:"type,omitempty"`
	Data      *map[string]interface{} `bson:"data" json:"data,omitempty"`
	CreatedAt *time.Time              `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt *time.Time              `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	Status    string                  `bson:"status,omitempty" json:"status,omitempty"`
}
