package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	signIn = "/signin"
	signUp = "/signup"
)

type authHandler struct {
	log         *logrus.Entry
	authService AuthService
}

func NewHandler(authService AuthService, log *logrus.Entry) *authHandler {
	return &authHandler{
		log:         log,
		authService: authService,
	}
}

func (h *authHandler) Register(router *gin.Engine) {
	auth := router.Group("/auth")
	{
		auth.POST(signIn, h.signIn)
		auth.POST(signUp, h.signUp)
	}
}

func (h *authHandler) signIn(c *gin.Context) {

}

// Регистрация
func (h *authHandler) signUp(c *gin.Context) {
	var input User

	if err := c.BindJSON(&input); err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	id, err := h.authService.CreateUser(input)
	if err != nil {
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"id": id,
	})
}

func (h *authHandler) newErrorResponse(c *gin.Context, statusCode int, message string) {
	h.log.Errorf(message)
	c.AbortWithStatusJSON(statusCode, &response{
		Success: false,
		Message: message,
	})
}
