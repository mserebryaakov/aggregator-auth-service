package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	CreateUser(*User) (uint, error)
	UpdateUser(*User) error
	LoginUser(email, password string) (string, error)
	GetUserById(id uint) (*User, error)
	SetRoleByCode(id uint, code string) error
}

type authService struct {
	storage   Storage
	logger    *logrus.Entry
	jwtSecret string
}

func NewService(storage Storage, log *logrus.Entry, jwtSecret string) AuthService {
	return &authService{
		storage:   storage,
		logger:    log,
		jwtSecret: jwtSecret,
	}
}

func (s *authService) GetUserById(id uint) (*User, error) {
	user, err := s.storage.GetUserById(id)
	if err != nil {
		return nil, err
	}

	if user.ID == 0 {
		return nil, errUserNotFound
	}

	return user, nil
}

func (s *authService) CreateUser(user *User) (uint, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		return 0, errFailedHashPassword
	}

	newUser := User{
		Email:    user.Email,
		Password: string(hash),
		Name:     user.Name,
		Surname:  user.Surname,
		Address:  user.Address,
		Blocked:  user.Blocked,
		RoleID:   user.RoleID,
	}

	return s.storage.CreateUser(&newUser)
}

func (s *authService) UpdateUser(iuser *User) error {
	user, err := s.storage.GetUserById(iuser.ID)
	if err != nil {
		return err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		return errFailedHashPassword
	}

	user.Email = iuser.Email
	user.Password = string(hash)
	user.Name = iuser.Name
	user.Surname = iuser.Surname
	user.Address = iuser.Address
	user.Blocked = iuser.Blocked
	user.RoleID = iuser.RoleID

	err = s.storage.UpdateUser(user)
	if err != nil {
		return err
	}

	return nil
}

func (s *authService) LoginUser(email, password string) (string, error) {
	user, err := s.storage.GetUserByEmail(email)
	if err != nil {
		return "", err
	}

	if user.ID == 0 {
		return "", errFailedPasswordOrEmail
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", errFailedPasswordOrEmail
	}

	var roleId uint = 0
	if user.RoleID != nil {
		roleId = *user.RoleID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID,
		"exp":  time.Now().Add(time.Hour * 24 * 30).Unix(),
		"role": roleId,
	})

	tokenString, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", errFailedCreateToken
	}

	return tokenString, nil
}

func (s *authService) SetRoleByCode(id uint, code string) error {
	user, err := s.storage.GetUserById(id)
	if err != nil {
		return err
	}

	if user.ID == 0 {
		return errUserNotFound
	}

	role, err := s.storage.GetRoleByCode(code)
	if err != nil {
		return err
	}

	if role.ID == 0 {
		return errRoleNotFound
	}

	user.RoleID = &role.ID
	err = s.storage.UpdateUser(user)
	if err != nil {
		return err
	}

	return nil
}
