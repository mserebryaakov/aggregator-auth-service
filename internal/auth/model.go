package auth

import "gorm.io/gorm"

type Area struct {
	gorm.Model
	Domain string `gorm:"unique" json:"domain"`
}

type User struct {
	gorm.Model
	Email           string `gorm:"unique" json:"email"`
	Password        string `json:"password"`
	Name            string `json:"name"`
	Surname         string `json:"surname"`
	Address         string `json:"address"`
	AddressesShopID []uint `gorm:"type:integer[]" json:"addresses_shop_id"`
	Blocked         bool   `json:"blocked"`
	RoleID          *uint  `json:"role_id"`
	Role            Role   `gorm:"foreignKey:RoleID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;" json:"-"`
}

type Role struct {
	gorm.Model
	Code string `gorm:"unique" json:"code"`
}
