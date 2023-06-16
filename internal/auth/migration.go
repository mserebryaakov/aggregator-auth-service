package auth

import "gorm.io/gorm"

func RunSchemaMigration(db *gorm.DB) error {
	migrator := db.Migrator()

	systemRole := Role{Code: "system"}

	if !migrator.HasTable(&Role{}) {
		db.AutoMigrate(&Role{})
		db.Create(&Role{Code: "admin"})
		db.Create(&Role{Code: "delivery"})
		db.Create(&Role{Code: "client"})
		db.Create(&systemRole)
	}

	if !migrator.HasTable(&User{}) {
		db.AutoMigrate(&User{})
		db.Create(&User{
			Email:           "supervisor@secret.secret",
			Password:        "$2a$10$8C5upPPRN.ViUta6sLEi0OrmOOsskaQn49XsnYB/J4PxtTo3SSfp6",
			RoleID:          &systemRole.ID,
			AddressesShopID: []uint{},
		})
	}

	return nil
}

func RunAuthServiceMigration(db *gorm.DB) error {
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
