package auth

import "gorm.io/gorm"

func RunSchemaMigration(db *gorm.DB) error {
	migrator := db.Migrator()

	if !migrator.HasTable(&Role{}) {
		db.AutoMigrate(&Role{})
		db.Create(&Role{Code: "admin"})
		db.Create(&Role{Code: "delivery"})
		db.Create(&Role{Code: "client"})
		db.Create(&Role{Code: "system"})
	}

	if !migrator.HasTable(&User{}) {
		db.AutoMigrate(&User{})
		var systemRole uint = 4
		db.Create(&User{Email: "supervisor@secret.secret", Password: "$2a$10$8C5upPPRN.ViUta6sLEi0OrmOOsskaQn49XsnYB/J4PxtTo3SSfp6", RoleID: &systemRole})
	}

	return nil
}

func RunAuthMigration(db *gorm.DB) error {
	return db.AutoMigrate(&Area{})
}
