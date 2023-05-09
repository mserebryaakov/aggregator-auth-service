package auth

import (
	"fmt"

	"github.com/mserebryaakov/aggregator-auth-service/pkg/postgres"
)

type Storage interface {
	CreateUser(user *User, schema string) (uint, error)
	UpdateUser(user *User, schema string) error
	GetUserByEmail(email string, schema string) (*User, error)
	GetUserById(id uint, schema string) (*User, error)
	GetRoleByCode(code string, schema string) (*Role, error)
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
	fmt.Printf("domain storage.CreateUser - %s", schema)
	db, err := s.scp.GetConnectionPool(schema)
	if err != nil {
		return 0, err
	}
	result := db.Create(&user)
	if result.Error != nil {
		fmt.Printf("domain storage.CreateUser result.Error - %v", result.Error)
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
