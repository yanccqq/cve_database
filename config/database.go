package config

import (
	"fmt"
	"time"

	"github.com/yanccqq/cve_database/common"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

func InitSqlite() error {
	var err error
	absolutePath := common.GetCurrentAbsolutePathPathByCaller()
	db, err = gorm.Open(sqlite.Open(absolutePath+"/db/cve_database.db"), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("连接数据库失败")
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取sql.DB出现异常")
	}
	// SetMaxIdleConns 设置空闲连接池中连接的最大数量
	sqlDB.SetMaxIdleConns(10)
	// SetMaxOpenConns 设置打开数据库连接的最大数量。
	sqlDB.SetMaxOpenConns(100)
	// SetConnMaxLifetime 设置了连接可复用的最大时间。
	sqlDB.SetConnMaxLifetime(time.Hour)
	return nil
}

func GetDB() (*gorm.DB, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库连接失败")
	}
	return db, nil
}
