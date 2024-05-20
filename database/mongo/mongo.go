package mongo

import (
	"context"
	"fmt"

	"dev.balaganapathy/uni-api-server/config"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	admins   = "ADMINS"
	users    = "USERS"
	settings = "SETTINGS"
)

var Collection struct {
	Admins   *mongo.Collection
	Users    *mongo.Collection
	Settings *mongo.Collection
}

// CONNECT MONGODB FUNC
func ConnectMongoDB() {
	uri := fmt.Sprintf(
		config.Getenv("MONGO_URI"),
		config.Getenv("MONGO_USERNAME"),
		config.Getenv("MONGO_PASSWORD"),
		config.Getenv("MONGO_HOST"),
		config.Getenv("MONGO_DATABASE"),
	)

	// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	client, err := mongo.Connect(
		context.Background(),
		options.Client().ApplyURI(uri),
	)
	if err != nil {
		fmt.Printf("[ERROR][DATABASE][MONGODB]: MongoDB Connection :%v", err)
		return
	}

	err = client.Ping(context.Background(), readpref.Primary())
	if err != nil {
		fmt.Printf("[ERROR][DATABASE][MONGODB]: MongoDB Ping :%v", err)
		return
	}

	fmt.Println("[INFO][DATABASE][MONGODB]: MongoDB Ping Successfully")

	db := client.Database("UNIDB")

	Collection.Admins = db.Collection(admins)
	Collection.Users = db.Collection(users)
	Collection.Settings = db.Collection(settings)
}
