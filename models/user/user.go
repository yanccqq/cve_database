package user

type User struct {
	Id    string `json:"id" gorm:"not null;primaryKey;column:id" binding:"required"`
	Token string `json:"token" gorm:"not null;column:token" binding:"required"`
}

type Tabler interface {
	TableName() string
}

func (User) TableName() string {
	return "user"
}

