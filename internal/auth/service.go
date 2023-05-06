package auth

import (
	"github.com/sirupsen/logrus"
)

type AuthService interface {
	CreateUser(user User) (string, error)
}

type authService struct {
	storage Storage
	logger  *logrus.Entry
}

func NewService(storage Storage, log *logrus.Entry) AuthService {
	return &authService{
		storage: storage,
		logger:  log,
	}
}

func (s *authService) CreateUser(user User) (string, error) {
	user.Password = generatePasswordHash(user.Password)
	return s.storage.CreateUser(user)
}
