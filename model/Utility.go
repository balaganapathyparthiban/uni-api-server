package model

import "go.mongodb.org/mongo-driver/bson/primitive"

type Coordinate = [2]int

type GeoLocation struct {
	Type        string      `json:"type"`
	Coordinates *Coordinate `json:"coordinates"`
}

type Location struct {
	Area        string      `json:"area"`
	City        string      `json:"city"`
	State       string      `json:"state"`
	Country     string      `json:"country"`
	Coordinates *Coordinate `json:"coordinates"`
}

type Address struct {
	Tag         string      `json:"tag"`
	DoorNo      string      `json:"doorNo"`
	Street      string      `json:"street"`
	City        string      `json:"city"`
	State       string      `json:"state"`
	Country     string      `json:"country"`
	Landmark    string      `json:"landmark"`
	Coordinates *Coordinate `json:"coordinates"`
}

type Phone struct {
	Code   string `bson:"code,omitempty" json:"code,omitempty"`
	Number string `bson:"number,omitempty" json:"number,omitempty"`
}

type Device struct {
	ID       *primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	Name     string              `bson:"device,omitempty" json:"device,omitempty"`
	FcmToken string              `bson:"fcmToken,omitempty" json:"fcmToken,omitempty"`
}

var Status = &struct {
	Pending string
	Active  string
	Blocked string
}{
	Pending: "PENDING",
	Active:  "ACTIVE",
	Blocked: "BLOCKED",
}
