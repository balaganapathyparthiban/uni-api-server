package model

type Location struct {
	Type        string `json:"type"`
	Coordinates []int  `json:"coordinates"`
}

type Phone struct {
	Code   string `bson:"code,omitempty" json:"code,omitempty"`
	Number string `bson:"number,omitempty" json:"number,omitempty"`
}

type Device struct {
	ID       string `bson:"_id,omitempty" json:"_id,omitempty"`
	Name     string `bson:"device,omitempty" json:"device,omitempty"`
	FcmToken string `bson:"fcmToken,omitempty" json:"fcmToken,omitempty"`
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
