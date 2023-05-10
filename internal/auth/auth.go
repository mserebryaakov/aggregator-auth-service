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

var (
	systemRole   string = "system"
	clientRole   string = "client"
	deliveryRole string = "delivery"
	adminRole    string = "admin"
)

var roleMap map[uint]string = map[uint]string{
	1: adminRole,
	2: deliveryRole,
	3: clientRole,
	4: systemRole,
}
