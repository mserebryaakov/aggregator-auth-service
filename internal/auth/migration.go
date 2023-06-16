package auth

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func RunSchemaMigration(db *gorm.DB, password, email string) error {
	migrator := db.Migrator()

	systemRole := Role{Code: "system"}

	if !migrator.HasTable(&Role{}) {
		db.AutoMigrate(&Role{})
		db.Create(&Role{Code: "admin"})
		db.Create(&Role{Code: "delivery"})
		db.Create(&Role{Code: "client"})
		db.Create(&systemRole)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return errFailedHashPassword
	}

	if !migrator.HasTable(&User{}) {
		db.AutoMigrate(&User{})
		db.Create(&User{
			Email:           email,
			Password:        string(hash),
			RoleID:          &systemRole.ID,
			AddressesShopID: []uint{},
		})
	}

	return nil
}

func RunAuthServiceMigration(db *gorm.DB, password, email string) error {
	err := RunSchemaMigration(db, password, email)
	if err != nil {
		return err
	}

	migrator := db.Migrator()
	if !migrator.HasTable(&Area{}) {
		err := db.AutoMigrate(&Area{})
		if err != nil {
			return err
		}
		db.Create(&Area{Domain: "public"})
	}

	return nil
}
