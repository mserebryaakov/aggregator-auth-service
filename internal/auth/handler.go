package auth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

const (
	loginPath    = "/login"
	signUpPath   = "/signup"
	validatePath = "/validate"
	userRolePath = "/role"
)

type authHandler struct {
	log         *logrus.Entry
	authService AuthService
	jwtSecret   string
}

func NewHandler(authService AuthService, log *logrus.Entry, jwtSecret string) *authHandler {
	return &authHandler{
		log:         log,
		authService: authService,
		jwtSecret:   jwtSecret,
	}
}

func (h *authHandler) Register(router *gin.Engine) {
	auth := router.Group("/auth")
	{
		auth.POST(loginPath, DomainMiddleware, h.login)
		auth.POST(signUpPath, DomainMiddleware, h.signup)
		auth.GET(validatePath, DomainMiddleware, h.validate)
	}
	user := router.Group("/user")
	{
		user.POST(userRolePath, DomainMiddleware, h.setRole)
		user.POST("", DomainMiddleware, h.createUser)
		user.PATCH("", DomainMiddleware, h.updateUser)
	}

	init := router.Group("/init")
	{
		init.POST("/start", h.initstart)
		init.POST("/rollback", h.initrollback)
	}
}

func (h *authHandler) login(c *gin.Context) {
	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	token, err := h.authService.LoginUser(body.Email, body.Password, domain)
	if err != nil {
		if err == errFailedPasswordOrEmail {
			h.newErrorResponse(c, http.StatusBadRequest, "incorrect email or password")
			return
		}

		h.newErrorResponse(c, http.StatusInternalServerError, "login server error")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", token, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{})
}

func (h *authHandler) signup(c *gin.Context) {
	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	var adminRole uint = 1
	id, err := h.authService.CreateUser(&User{Email: body.Email, Password: body.Password, RoleID: &adminRole}, domain)
	if err != nil {
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}

func (h *authHandler) validate(c *gin.Context) {
	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	tokenString := c.Request.Header.Get("Authorization")

	if tokenString == "" {
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(h.jwtSecret), nil
	})
	if err != nil {
		h.log.Debugf("error jwt parse token: %v", err)
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		userId, ok := claims["sub"].(float64)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		user, err := h.authService.GetUserById(uint(userId), domain)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
		}

		c.JSON(http.StatusOK, user)
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func (h *authHandler) setRole(c *gin.Context) {
	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Id   uint
		Role string
	}

	if c.Bind(&body) != nil {
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	err = h.authService.SetRoleByCode(body.Id, body.Role, domain)
	if err != nil {
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *authHandler) createUser(c *gin.Context) {
	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body User = User{}

	if c.Bind(&body) != nil {
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	id, err := h.authService.CreateUser(&body, domain)
	if err != nil {
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}

func (h *authHandler) updateUser(c *gin.Context) {
	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body User = User{}

	if c.Bind(&body) != nil {
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	err = h.authService.UpdateUser(&body, domain)
	if err != nil {
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *authHandler) initstart(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}

func (h *authHandler) initrollback(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}

type response struct {
	Message string `json:"message"`
}

func (h *authHandler) newErrorResponse(c *gin.Context, statusCode int, message string) {
	h.log.Errorf(message)
	c.AbortWithStatusJSON(statusCode, &response{
		Message: message,
	})
}

func (h *authHandler) getDomain(c *gin.Context) (string, error) {
	domain, exists := c.Get("domain")
	if exists {
		domainStr, ok := domain.(string)
		if ok {
			return domainStr, nil
		} else {
			return "", fmt.Errorf("incorrect domain type - %v", domain)
		}
	} else {
		return "", fmt.Errorf("domain not found")
	}
}
