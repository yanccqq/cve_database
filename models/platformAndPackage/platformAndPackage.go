package platformAndPackage


type PlatformAndPackage struct {
	Id              string `json:"id" gorm:"not null;primaryKey;column:id" binding:"required"`
	LoopholeCve     string `json:"loopholeCve" gorm:"column:loophole_cve" binding:"required"`
	Platform        string `json:"platform" gorm:"column:platform" binding:"required"`
	SoftwarePackage string `json:"softwarePackage" gorm:"column:software_package" binding:"required"`
}

type Tabler interface {
	TableName() string
}

func (PlatformAndPackage) TableName() string {
	return "platform_and_package"
}
