package auth

import "errors"

var (
	errFailedHashPassword         = errors.New("failed to hash password")
	errFailedCreateToken          = errors.New("error create token")
	errFailedPasswordOrEmail      = errors.New("failed password or email")
	errUserNotFound               = errors.New("user not found")
	errRoleNotFound               = errors.New("role not found")
	errAreaNotFound               = errors.New("area not found")
	errUserWithEmailAlreadyExists = errors.New("user already exists")
)
