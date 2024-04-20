package mysql

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB

// CONNECT MYSQL FUNC
func ConnectMysqlDB() {
	dns := "root:docker-pwd@tcp(localhost:3306)/UNSEEN_DB?parseTime=true"
	db, err := gorm.Open(
		mysql.Open(dns),
		&gorm.Config{},
	)
	if err != nil {
		panic(err)
	}

	db.Set("gorm:table_options", "ENGINE=InnoDB")

	sqlDB, err := db.DB()
	if err != nil {
		panic(err)
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	DB = db

	fmt.Printf("%s", "Connected To Database")
}
