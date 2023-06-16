package auth

import (
	"errors"
	"strings"
)

var (
	errFailedHashPassword         = errors.New("failed to hash password")
	errFailedCreateToken          = errors.New("error create token")
	errFailedPasswordOrEmail      = errors.New("failed password or email")
	errUserNotFound               = errors.New("user not found")
	errRoleNotFound               = errors.New("role not found")
	errAreaNotFound               = errors.New("area not found")
	errUserWithEmailAlreadyExists = errors.New("user already exists")
)

const (
	HttpErrNotFound = iota
	HttpErrNotStatusOK
)

type ConstCodeAppError int

type AppError struct {
	Code     ConstCodeAppError
	Msg      string
	Err      error
	HTTPCode int
}

func New(code ConstCodeAppError, msg string, httpCode int, err error) error {
	return &AppError{
		Code:     code,
		Msg:      msg,
		Err:      err,
		HTTPCode: httpCode,
	}
}

func (ae *AppError) Error() string {
	b := new(strings.Builder)
	b.WriteString(ae.Msg + " ")
	if ae.Err != nil {
		b.WriteByte('(')
		b.WriteString(ae.Err.Error())
		b.WriteByte(')')
	}
	return b.String()
}

func (ae *AppError) Unwrap() error {
	return ae.Err
}
