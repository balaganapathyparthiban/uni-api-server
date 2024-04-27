package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"dev.balaganapathy/uni-server/model"
	"github.com/gofiber/fiber/v2"
)

func ParseBufferFromMultipartFile(file *multipart.FileHeader) (*bytes.Buffer, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buffer := bytes.NewBuffer(nil)
	if _, err := io.Copy(buffer, f); err != nil {
		return nil, err
	}

	return buffer, nil
}

func GetRouteFromValhalla(body *model.ValhallaRequestBody) (*model.ValhallaRoute, error) {
	// Construct Request Body
	valhallaURL := "http://localhost:8002/route"
	data := map[string]interface{}{
		"locations": []map[string]interface{}{
			{"lat": body.PickupLatitude, "lon": body.PickupLongitude},
			{"lat": body.DropLatitude, "lon": body.DropLongitude},
		},
		"costing": "auto",
	}
	dataStringify, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Make Http GET Request To Valhalla
	url := fmt.Sprintf("%s?json=%s", valhallaURL, dataStringify)

	// Make Http GET Request To Valhalla
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	// Read Http Response Body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err

	}

	// Parse Http Response Body
	parsedBody := new(model.ValhallaRoute)
	err = json.Unmarshal(respBody, &parsedBody)
	if err != nil || parsedBody.Trip.Language == "" {
		return nil, err

	}

	return parsedBody, nil
}

func ConstructUserInfo(userInfo *model.User) *fiber.Map {
	return &fiber.Map{
		"_id":          &userInfo.ID,
		"email":        &userInfo.Email,
		"avatar":       &userInfo.Avatar,
		"fullName":     &userInfo.FullName,
		"phone":        &userInfo.Phone,
		"isRegistered": &userInfo.IsRegistered,
		"language":     &userInfo.Language,
		"status":       &userInfo.Status,
	}
}
