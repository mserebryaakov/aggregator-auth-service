package auth

import "gorm.io/gorm"

type Area struct {
	gorm.Model
	Domain string `gorm:"unique"`
}

type User struct {
	gorm.Model
	Email    string `gorm:"unique"`
	Password string
	Name     string
	Surname  string
	Address  string
	Blocked  bool
	RoleID   *uint
	Role     Role `gorm:"foreignKey:RoleID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

type Role struct {
	gorm.Model
	Code string `gorm:"unique"`
}
