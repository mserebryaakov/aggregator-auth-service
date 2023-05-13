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
	scp *postgres.SchemaConnectionPool
}

func NewStorage(scp *postgres.SchemaConnectionPool) Storage {
	return &AuthStorage{
		scp: scp,
	}
}

func (s *AuthStorage) CreateUser(user *User, schema string) (uint, error) {
	db, err := s.scp.GetConnectionPool(schema)
	if err != nil {
		return 0, err
	}
	result := db.Create(&user)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to create user")
	}
	return user.ID, nil
}

func (s *AuthStorage) GetUserByEmail(email string, schema string) (*User, error) {
	db, err := s.scp.GetConnectionPool(schema)
	if err != nil {
		return nil, err
	}

	var user User
	result := db.First(&user, "email = ?", email)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user")
	}
	return &user, nil
}

func (s *AuthStorage) GetUserById(id uint, schema string) (*User, error) {
	db, err := s.scp.GetConnectionPool(schema)
	if err != nil {
		return nil, err
	}

	var user User
	result := db.First(&user, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find user")
	}
	return &user, nil
}

func (s *AuthStorage) GetRoleByCode(code string, schema string) (*Role, error) {
	db, err := s.scp.GetConnectionPool(schema)
	if err != nil {
		return nil, err
	}

	var role Role
	result := db.First(&role, "code = ?", code)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find user")
	}
	return &role, nil
}

func (s *AuthStorage) UpdateUser(user *User, schema string) error {
	db, err := s.scp.GetConnectionPool(schema)
	if err != nil {
		return err
	}

	result := db.Save(user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (s *AuthStorage) CreateArea(area *Area) (uint, error) {
	db, err := s.scp.GetConnectionPool("public")
	if err != nil {
		return 0, err
	}
	result := db.Create(&area)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to create area")
	}
	return area.ID, nil
}

func (s *AuthStorage) GetAllArea() ([]Area, error) {
	db, err := s.scp.GetConnectionPool("public")
	if err != nil {
		return nil, err
	}
	var area []Area
	result := db.Find(&area)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get all area")
	}
	return area, nil
}

func (s *AuthStorage) GetAreaByDomain(domain string) (*Area, error) {
	db, err := s.scp.GetConnectionPool("public")
	if err != nil {
		return nil, err
	}

	var area Area
	result := db.First(&area, "domain = ?", domain)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get area")
	}
	return &area, nil
}

func (s *AuthStorage) CreateSchema(domain string) error {
	publicschema, err := s.scp.GetConnectionPool("public")
	if err != nil {
		return err
	}

	tx := publicschema.Begin()
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

	err = tx.Commit().Error
	if err != nil {
		return err
	}

	resschema, err := s.scp.GetConnectionPool(domain)
	if err != nil {
		return err
	}

	err = RunSchemaMigration(resschema)
	if err != nil {
		fmt.Printf("Fatal create schema - failed migrations - %s", domain)
		return err
	}

	return nil
}

func (s *AuthStorage) DeleteArea(domain string) error {
	publicschema, err := s.scp.GetConnectionPool("public")
	if err != nil {
		return err
	}

	result := publicschema.Where("domain = ?", domain).Delete(&Area{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete area")
	}

	return nil
}

func (s *AuthStorage) DeleteSchema(domain string) error {
	publicschema, err := s.scp.GetConnectionPool("public")
	if err != nil {
		return err
	}

	if err := publicschema.Exec("DROP SCHEMA IF EXISTS " + domain + " CASCADE").Error; err != nil {
		return err
	}

	return nil
}
