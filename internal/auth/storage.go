package auth

import (
	"fmt"

	"github.com/jmoiron/sqlx"
)

const (
	userT = "users"
)

type Storage interface {
	CreateUser(user User) (string, error)
}

type AuthStorage struct {
	db *sqlx.DB
}

func NewStorage(db *sqlx.DB) Storage {
	return &AuthStorage{
		db: db,
	}
}

func (s *AuthStorage) CreateUser(user User) (string, error) {
	var id string
	query := fmt.Sprintf("INSERT INTO %s (email, password, name, surname, address) values ($1, $2, $3, $4, $5) RETURNING id", userT)
	row := s.db.QueryRow(query, user.Email, user.Password, user.Name, user.Surname, user.Address)
	if err := row.Scan(&id); err != nil {
		return "", err
	}

	return id, nil
}
