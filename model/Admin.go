package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

var AdminType = &struct {
	Admin    string
	SubAdmin string
}{
	Admin:    "ADMIN",
	SubAdmin: "SUB_ADMIN",
}

type AdminPrivilegeRule struct {
	Read      bool `bson:"read" json:"read,omitempty"`
	ReadWrite bool `bson:"readWrite" json:"readWrite,omitempty"`
	Delete    bool `bson:"delete" json:"delete,omitempty"`
}

type AdminPrivilege struct {
	Admin   *AdminPrivilegeRule `bson:"admin" json:"admin,omitempty"`
	User    *AdminPrivilegeRule `bson:"user" json:"user,omitempty"`
	Setting *AdminPrivilegeRule `bson:"setting" json:"setting,omitempty"`
}

type Admin struct {
	Type      string              `bson:"type" json:"type,omitempty"`
	ID        *primitive.ObjectID `bson:"_id" json:"_id,omitempty"`
	GoogleId  string              `bson:"googleId" json:"googleId,omitempty"`
	Email     string              `bson:"email,omitempty" json:"email,omitempty"`
	Privilege *AdminPrivilege     `bson:"privilege,omitempty" json:"privilege,omitempty"`
	CreatedAt *time.Time          `bson:"createdAt,omitempty" json:"createdAt,omitempty"`
	UpdatedAt *time.Time          `bson:"updatedAt,omitempty" json:"updatedAt,omitempty"`
	Status    string              `bson:"status,omitempty" json:"status,omitempty"`
}
