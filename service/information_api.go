package service

import (
	"github.com/yanccqq/cve_database/config"
	"github.com/yanccqq/cve_database/models/information"
)

type InformationApi struct{}

/**
* 获取全部的漏洞信息
**/
func (informationApi *InformationApi) ListAll() ([]information.Information, error) {
	db, error := config.GetDB()
	if error != nil {
		return nil, error
	}

	var informations []information.Information
	result := db.Debug().Model(&information.Information{}).Select([]string{"loophole_cve", "loophole_information", "loophole_cvss", "update_time", "reference_link"}).Order("update_time desc").Find(&informations)
	return informations, result.Error
}

func (informationApi *InformationApi) GetInformationByCVE(cve string) (information.Information, error) {
	var i information.Information
	db, error := config.GetDB()
	if error != nil {
		return i, error
	}
	result := db.Model(&information.Information{}).Preload("PlatformAndPackages").First(&i, "loophole_cve = ?", cve)
	return i, result.Error
}

func (informationApi *InformationApi) UpdateInformationByCVE(cve string) (error) {
	db, error := config.GetDB()
	if error != nil {
		return  error
	}
	result := db.Model(&information.Information{}).Where("loophole_cve = ?", cve).Update("export_flag", 1)
	return result.Error
}
