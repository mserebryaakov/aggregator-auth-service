package auth

import (
	"github.com/sirupsen/logrus"
)

type AuthLogHook struct{}

func (h *AuthLogHook) Fire(entry *logrus.Entry) error {
	entry.Message = "Auth: " + entry.Message
	return nil
}

func (h *AuthLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
