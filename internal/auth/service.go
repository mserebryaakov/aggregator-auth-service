package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type AuthService interface {
	CreateUser(user *User, schema string) (uint, error)
	UpdateUser(user *User, schema string) error
	LoginUser(email, password, schema string) (string, error)
	GetUserById(id uint, schema string) (*User, error)
	SetRoleByCode(id uint, code string, schema string) error
	GetAreaByDomain(domain string) (*Area, error)
	CreateArea(domain string) (uint, error)
	DeleteArea(domain string) error
	CreateSchema(domain string) error
	DeleteSchema(domain string) error
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

func (s *authService) GetUserById(id uint, schema string) (*User, error) {
	user, err := s.storage.GetUserById(id, schema)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, errUserNotFound
	}

	return user, nil
}

func (s *authService) CreateUser(user *User, schema string) (uint, error) {
	tuser, err := s.storage.GetUserByEmail(user.Email, schema)
	if err != nil {
		return 0, err
	}
	if tuser != nil {
		return 0, errUserWithEmailAlreadyExists
	}

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

	return s.storage.CreateUser(&newUser, schema)
}

func (s *authService) UpdateUser(user *User, schema string) error {
	iuser, err := s.storage.GetUserById(user.ID, schema)
	if err != nil {
		return err
	}

	if iuser == nil {
		return errUserNotFound
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		return errFailedHashPassword
	}

	iuser.Email = user.Email
	iuser.Password = string(hash)
	iuser.Name = user.Name
	iuser.Surname = user.Surname
	iuser.Address = user.Address
	iuser.Blocked = user.Blocked
	iuser.RoleID = user.RoleID

	err = s.storage.UpdateUser(iuser, schema)
	if err != nil {
		return err
	}

	return nil
}

func (s *authService) LoginUser(email, password, schema string) (string, error) {
	user, err := s.storage.GetUserByEmail(email, schema)
	if err != nil {
		return "", err
	}

	if user == nil {
		return "", errFailedPasswordOrEmail
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return "", errFailedPasswordOrEmail
	}

	var roleId uint = 0
	if user.RoleID != nil {
		roleId = *user.RoleID
	} else {
		return "", errRoleNotFound
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":    user.ID,
		"exp":    time.Now().Add(time.Hour * 24 * 30).Unix(),
		"role":   roleMap[roleId],
		"domain": schema,
	})

	tokenString, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", errFailedCreateToken
	}

	return tokenString, nil
}

func (s *authService) SetRoleByCode(id uint, code, schema string) error {
	user, err := s.storage.GetUserById(id, schema)
	if err != nil {
		return err
	}

	if user == nil {
		return errUserNotFound
	}

	role, err := s.storage.GetRoleByCode(code, schema)
	if err != nil {
		return err
	}

	if role == nil {
		return errRoleNotFound
	}

	user.RoleID = &role.ID
	err = s.storage.UpdateUser(user, schema)
	if err != nil {
		return err
	}

	return nil
}

func (s *authService) GetAreaByDomain(domain string) (*Area, error) {
	area, err := s.storage.GetAreaByDomain(domain)
	if err != nil {
		return nil, err
	}

	if area == nil {
		return nil, errAreaNotFound
	}

	return area, nil
}

func (s *authService) CreateArea(domain string) (uint, error) {
	newArea := Area{
		Domain: domain,
	}

	return s.storage.CreateArea(&newArea)
}

func (s *authService) CreateSchema(domain string) error {
	return s.storage.CreateSchema(domain)
}

func (s *authService) DeleteArea(domain string) error {
	return s.storage.DeleteArea(domain)
}

func (s *authService) DeleteSchema(domain string) error {
	return s.storage.DeleteSchema(domain)
}
