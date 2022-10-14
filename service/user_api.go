package service

import (
	"github.com/yanccqq/cve_database/config"
	"github.com/yanccqq/cve_database/models/user"
)

type UserApi struct{}

func (userApi *UserApi) Get() (user.User, error) {
	var u user.User
	db, error := config.GetDB()
	if error != nil {
		return u, error
	}

	result := db.Model(&user.User{}).First(&u)
	return u, result.Error
}

/**
* 插入用户信息
**/
func (userApi *UserApi) Add(u *user.User) error {
	db, error := config.GetDB()
	if error != nil {
		return error
	}
	result := db.Where("1 = 1").Delete(&user.User{})
	if result.Error != nil {
		return result.Error
	}
	result = db.Create(u)
	return result.Error
}

func (userApi *UserApi) RemoveAll() error {
	db, error := config.GetDB()
	if error != nil {
		return error
	}
	result := db.Where("1 = 1").Delete(&user.User{})
	return result.Error
}
