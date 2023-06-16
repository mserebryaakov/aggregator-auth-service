package auth

import (
	"github.com/sirupsen/logrus"
)

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

func getAdminRoleId() *uint {
	var adminRole uint = 1
	return &adminRole
}

func getClientRoleId() *uint {
	var clientRole uint = 3
	return &clientRole
}

type AuthLogHook struct{}

func (h *AuthLogHook) Fire(entry *logrus.Entry) error {
	entry.Message = "Auth: " + entry.Message
	return nil
}

func (h *AuthLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}
