package auth

import (
	"errors"
	"fmt"

	"github.com/mserebryaakov/aggregator-auth-service/pkg/postgres"
	"gorm.io/gorm"
)

type Storage interface {
	CreateUser(user *User, schema string) (uint, error)
	UpdateUser(user *User, schema string) error
	GetUserByEmail(email string, schema string) (*User, error)
	GetUserById(id uint, schema string) (*User, error)
	GetRoleByCode(code string, schema string) (*Role, error)
	CreateArea(area *Area) (uint, error)
	GetAllArea() ([]Area, error)
	GetAreaByDomain(domain string) (*Area, error)
	DeleteArea(domain string) error
	CreateSchema(domain string) error
	DeleteSchema(domain string) error
}

type AuthStorage struct {
	scp                *postgres.SchemaConnectionPool
	SupervisorEmail    string
	SupervisorPassword string
}

func NewStorage(scp *postgres.SchemaConnectionPool, supervisorEmail, supervisorPassword string) Storage {
	return &AuthStorage{
		scp:                scp,
		SupervisorEmail:    supervisorEmail,
		SupervisorPassword: supervisorPassword,
	}
}

func (s *AuthStorage) withConnectionPool(fn func(db *gorm.DB) error, schema string) error {
	db, err := s.scp.GetConnectionPool(schema)
	if err != nil {
		return err
	}
	return fn(db)
}

func (s *AuthStorage) CreateUser(user *User, schema string) (uint, error) {
	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.Create(&user).Error
	}, schema)

	if err != nil {
		return 0, err
	}
	return user.ID, nil
}

func (s *AuthStorage) GetUserByEmail(email string, schema string) (*User, error) {
	var user User

	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.First(&user, "email = ?", email).Error
	}, schema)

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *AuthStorage) GetUserById(id uint, schema string) (*User, error) {
	var user User

	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.First(&user, id).Error
	}, schema)

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (s *AuthStorage) GetRoleByCode(code string, schema string) (*Role, error) {
	var role Role

	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.First(&role, "code = ?", code).Error
	}, schema)

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &role, nil
}

func (s *AuthStorage) UpdateUser(user *User, schema string) error {
	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.Save(user).Error
	}, schema)

	return err
}

func (s *AuthStorage) CreateArea(area *Area) (uint, error) {
	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.Create(&area).Error
	}, "public")

	if err != nil {
		return 0, err
	}

	return area.ID, nil
}

func (s *AuthStorage) GetAllArea() ([]Area, error) {
	var area []Area

	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.Find(&area).Error
	}, "public")

	if err != nil {
		return nil, err
	}

	return area, nil
}

func (s *AuthStorage) GetAreaByDomain(domain string) (*Area, error) {
	var area Area

	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.First(&area, "domain = ?", domain).Error
	}, "public")

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	return &area, nil
}

func (s *AuthStorage) CreateSchema(domain string) error {
	err := s.withConnectionPool(func(db *gorm.DB) error {
		tx := db.Begin()
		if tx.Error != nil {
			return tx.Error
		}

		var count int64
		tx.Raw("SELECT COUNT(*) FROM pg_namespace WHERE nspname = ?", domain).Scan(&count)
		if count != 0 {
			tx.Rollback()
			return fmt.Errorf("create schema failed (already exists): %s", domain)
		}

		if err := tx.Exec("CREATE SCHEMA IF NOT EXISTS " + domain).Error; err != nil {
			tx.Rollback()
			return err
		}

		err := tx.Commit().Error
		if err != nil {
			return err
		}

		resschema, err := s.scp.GetConnectionPool(domain)
		if err != nil {
			return err
		}

		err = RunSchemaMigration(resschema, s.SupervisorPassword, s.SupervisorEmail)
		if err != nil {
			return err
		}

		return nil
	}, "public")

	return err
}

func (s *AuthStorage) DeleteArea(domain string) error {
	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.Where("domain = ?", domain).Delete(&Area{}).Error
	}, "public")

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}

	return err
}

func (s *AuthStorage) DeleteSchema(domain string) error {
	err := s.withConnectionPool(func(db *gorm.DB) error {
		return db.Exec("DROP SCHEMA IF EXISTS " + domain + " CASCADE").Error
	}, "public")

	return err
}
