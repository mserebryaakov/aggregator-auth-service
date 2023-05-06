package auth

import (
	"crypto/sha1"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	salt       = "hjqrhjqw124617ajfhajs"
	signingKey = "qrkjk#4#%35FSFJlja#4353KSFjH"
	tokenTTL   = 12 * time.Hour
)

func generatePasswordHash(password string) string {
	hash := sha1.New()
	hash.Write([]byte(password))

	return fmt.Sprintf("%x", hash.Sum([]byte(salt)))
}

type response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type AuthLogHook struct{}

func (h *AuthLogHook) Fire(entry *logrus.Entry) error {
	entry.Message = "Auth: " + entry.Message
	return nil
}

func (h *AuthLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
