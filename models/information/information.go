package information

import (
	"github.com/yanccqq/cve_database/models/platformAndPackage"
	"gorm.io/plugin/soft_delete"
)

type Information struct {
	LoopholeCve         string                                  `json:"loopholeCve" gorm:"not null;primaryKey;column:loophole_cve" binding:"required"`
	LoopholeInformation string                                  `json:"loopholeInformation" gorm:"loophole_information" binding:"required"`
	LoopholeCvss        string                                  `json:"loopholeCvss" gorm:"column:loophole_cvss" binding:"required"`
	UpdateTime          string                                  `json:"updateTime" gorm:"column:update_time" binding:"required"`
	ReferenceLink       string                                  `json:"referenceLink" gorm:"column:reference_link" binding:"required"`
	Remarks             string                                  `json:"remarks" gorm:"column:remarks" binding:"required"`
	ExportFlag          soft_delete.DeletedAt                   `json:"exportFlag" gorm:"softDelete:flag;column:export_flag" binding:"required"`
	PlatformAndPackages []platformAndPackage.PlatformAndPackage `gorm:"foreignKey:LoopholeCve;references:LoopholeCve"`
}

type Tabler interface {
	TableName() string
}

func (Information) TableName() string {
	return "information"
}
