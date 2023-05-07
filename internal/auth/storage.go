package auth

import (
	"fmt"

	"gorm.io/gorm"
)

type Storage interface {
	CreateUser(user *User) (uint, error)
	UpdateUser(user *User) error
	GetUserByEmail(email string) (*User, error)
	GetUserById(id uint) (*User, error)
	GetRoleByCode(code string) (*Role, error)
}

type AuthStorage struct {
	db *gorm.DB
}

func NewStorage(db *gorm.DB) Storage {
	return &AuthStorage{
		db: db,
	}
}

func (s *AuthStorage) CreateUser(user *User) (uint, error) {
	result := s.db.Create(&user)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to create user")
	}
	return user.ID, nil
}

func (s *AuthStorage) GetUserByEmail(email string) (*User, error) {
	var user User
	result := s.db.First(&user, "email = ?", email)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get user")
	}
	return &user, nil
}

func (s *AuthStorage) GetUserById(id uint) (*User, error) {
	var user User
	result := s.db.First(&user, id)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to find user")
	}
	return &user, nil
}

func (s *AuthStorage) GetRoleByCode(code string) (*Role, error) {
	var role Role
	result := s.db.First(&role, "code = ?", code)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to find user")
	}
	return &role, nil
}

func (s *AuthStorage) UpdateUser(user *User) error {
	result := s.db.Save(user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
