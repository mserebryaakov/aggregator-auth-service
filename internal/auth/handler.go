package auth

import (
	"fmt"
	"net/http"
	"strings"
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
		auth.POST(loginPath, h.domainMiddleware, h.login)
		auth.POST(signUpPath, h.domainMiddleware, h.signup)
		auth.POST(validatePath, h.domainMiddleware, h.authWithRoleMiddleware([]string{}), h.validate)
	}

	user := router.Group("/user")
	{
		user.POST(userRolePath, h.domainMiddleware, h.authWithRoleMiddleware([]string{systemRole, adminRole}), h.setRole)
		user.POST("", h.domainMiddleware, h.authWithRoleMiddleware([]string{systemRole, adminRole}), h.createUser)
		user.PUT("", h.domainMiddleware, h.authWithRoleMiddleware([]string{systemRole, adminRole}), h.updateUser)
	}

	init := router.Group("/auth/init")
	{
		//init.POST("/start", h.authWithRoleMiddleware([]string{systemRole, adminRole}), h.initstart)
		init.POST("/start", h.initstart)
		init.POST("/rollback", h.authWithRoleMiddleware([]string{systemRole, adminRole}), h.initrollback)
	}

	system := router.Group("/system")
	{
		sestemAuthSub := system.Group("/auth")
		{
			sestemAuthSub.POST(validatePath, h.systemDomainMiddleware, h.authWithRoleMiddleware([]string{}), h.validate)
			sestemAuthSub.POST(loginPath, h.systemDomainMiddleware, h.login)
		}
	}
}

// Авторизация
func (h *authHandler) login(c *gin.Context) {
	h.log.Debugf("handler login")

	domain := h.getDomain(c)
	if domain == "" {
		h.log.Debug("login: domain is not defined")
		h.newErrorResponse(c, http.StatusBadRequest, "domain is not defined")
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.log.Debugf("login: failed to read body - %v", err)
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	h.log.Debugf("login: body - %+v", body)

	token, err := h.authService.LoginUser(body.Email, body.Password, domain)
	if err != nil {
		if err == errFailedPasswordOrEmail {
			h.log.Debug("login: failed password or email")
			h.newErrorResponse(c, http.StatusBadRequest, "incorrect email or password")
			return
		}

		h.log.Debugf("login: login server error - %v", err)
		h.newErrorResponse(c, http.StatusInternalServerError, "login server error")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", token, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{})
}

// Регистрация пользователя
func (h *authHandler) signup(c *gin.Context) {
	h.log.Debugf("login hadnler signup")

	domain := h.getDomain(c)
	if domain == "" {
		h.log.Debug("signup: domain is not defined")
		h.newErrorResponse(c, http.StatusBadRequest, "domain is not defined")
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.log.Debugf("signup: failed to read body - %v", err)
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	h.log.Debugf("signup: body - %+v", body)

	id, err := h.authService.CreateUser(&User{Email: body.Email, Password: body.Password, RoleID: getClientRoleId()}, domain)
	if err != nil {
		h.log.Debugf("signup: failed to create user with err - %s", err)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}

// Проверка прав токена
func (h *authHandler) validate(c *gin.Context) {
	h.log.Debugf("handler validate")

	var body struct {
		Role []string `json:"role"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.log.Debugf("validate: failed to read body - %v", err)
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	h.log.Debugf("validate: body - %+v", body)

	tokenString := c.Request.Header.Get("X-System-Token")

	if tokenString == "" {
		h.log.Debug("validate: system token is not defined")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(h.jwtSecret), nil
	})
	if err != nil {
		h.log.Debugf("validate: error jwt parse token: %v", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			h.log.Debugf("validate: token exp error - %s", tokenString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userId, ok := claims["sub"].(float64)
		if !ok {
			h.log.Debugf("validate: token sub error - %s", tokenString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		irole, ok := claims["role"].(string)
		if !ok {
			h.log.Debugf("validate: token role error - %s", tokenString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		found := false
		for _, str := range body.Role {
			if str == irole {
				found = true
				break
			}
		}

		if len(body.Role) == 0 {
			found = true
		}

		if !found {
			h.log.Debugf("validate: role not found in body.Role (role -%s, body.Role - %s)", irole, body.Role)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		domain := h.getDomain(c)
		if domain == "" {
			h.log.Debugf("validate: domain is not defined")
			h.newErrorResponse(c, http.StatusBadRequest, "domain is not defined")
			return
		}

		tokenDomain, ok := claims["domain"].(string)
		if (!ok || (domain != tokenDomain && irole != "system")) && irole != systemRole {
			h.log.Debugf("validate: url domain != token domain (urlDomain - %s, tokenDomain - %s) or tokenDomain domain failed", tokenDomain, tokenDomain)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"userId": userId,
		})
	} else {
		h.log.Debug("validate: token not valid")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

// Установка роли пользователю
func (h *authHandler) setRole(c *gin.Context) {
	h.log.Debugf("handler setRole")

	domain := h.getDomain(c)
	if domain == "" {
		h.log.Debug("setRole: domain is not defined")
		h.newErrorResponse(c, http.StatusBadRequest, "domain is not defined")
		return
	}

	var body struct {
		Id   uint   `json:"id"`
		Role string `json:"role"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.log.Debugf("setRole: failed to read body - %v", err)
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	if body.Id == 0 || body.Role == "" {
		h.log.Debug("setRole: invalid body (id = 0 or role = ``)")
		h.newErrorResponse(c, http.StatusBadRequest, "invalid body (id = 0 or role = ``)")
		return
	}

	h.log.Debugf("setRole: body - %+v", body)

	err := h.authService.SetRoleByCode(body.Id, body.Role, domain)
	if err != nil {
		h.log.Debugf("setRole: failed to setRole with err - %s", err)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// Создание пользователя
func (h *authHandler) createUser(c *gin.Context) {
	h.log.Debugf("handler createUser")

	domain := h.getDomain(c)
	if domain == "" {
		h.log.Debug("createUser: domain is not defined")
		h.newErrorResponse(c, http.StatusBadRequest, "domain is not defined")
		return
	}

	var body User = User{}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.log.Debugf("createUser: failed to read body - %v", err)
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	h.log.Debugf("createUser: body - %+v", body)

	id, err := h.authService.CreateUser(&body, domain)
	if err != nil {
		if err == errUserWithEmailAlreadyExists {
			h.log.Debugf("createUser: user with email (%s) already exist", body.Email)
			h.newErrorResponse(c, http.StatusConflict, err.Error())
			return
		}
		h.log.Debugf("createUser: failed create user with err - %s", err)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}

// Обновление пользователя
func (h *authHandler) updateUser(c *gin.Context) {
	h.log.Debugf("handler updateUser")

	domain := h.getDomain(c)
	if domain == "" {
		h.log.Debug("updateUser: domain is not defined")
		h.newErrorResponse(c, http.StatusBadRequest, "domain is not defined")
		return
	}

	var body User = User{}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.log.Debugf("updateUser: failed to read body - %v", err)
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	h.log.Debugf("updateUser: body - %+v", body)

	err := h.authService.UpdateUser(&body, domain)
	if err != nil {
		h.log.Errorf("updateUser: failed update user with err - %v", err)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// Инициализация площадки
func (h *authHandler) initstart(c *gin.Context) {
	h.log.Debugf("handler initstart")

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.log.Debugf("initstart: failed read body - %v", err)
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	h.log.Debugf("initstart: body - %+v", body)

	domain := c.Query("domain")
	if domain == "" {
		h.log.Errorf("initstart: missing query parameter (domain)")
		h.newErrorResponse(c, http.StatusBadRequest, "missing query parameter (domain)")
		return
	}

	_, err := h.authService.GetAreaByDomain(domain)
	if err != nil {
		if err != errAreaNotFound {
			h.log.Errorf("initstart: fatal error get area - %s, by domain - %s", err, domain)
			h.newErrorResponse(c, http.StatusBadRequest, "failed get domain")
			return
		}
	} else {
		h.log.Errorf("initstart: domain alreay exists - %s", domain)
		h.newErrorResponse(c, http.StatusBadRequest, "domain alreay exists")
		return
	}

	_, err = h.authService.CreateArea(domain)
	if err != nil {
		h.log.Errorf("initstart: create area err - %v", err)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	err = h.authService.CreateSchema(domain)
	if err != nil {
		h.log.Errorf("initstart: create schema err - %v", err)
		err := h.authService.DeleteArea(domain)
		if err != nil {
			h.log.Errorf("initstart: delete area after create schema err - %v", err)
		}
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	admin := User{Email: body.Email, Password: body.Password, RoleID: getAdminRoleId()}
	_, err = h.authService.CreateUser(&admin, domain)
	if err != nil {
		h.log.Errorf("initstart: failed create user - %v", err)
		err = h.authService.DeleteArea(domain)
		if err != nil {
			h.log.Errorf("initstart: failed delete area after create user err - %v", err)
		}
		err = h.authService.DeleteSchema(domain)
		if err != nil {
			h.log.Errorf("initstart: failed delete schema after create user err - %v", err)
		}
		h.newErrorResponse(c, http.StatusInternalServerError, "failed create admin user")
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

// Отмена инициализации площадки
func (h *authHandler) initrollback(c *gin.Context) {
	h.log.Debugf("handler initrollback")

	domain := c.Query("domain")
	if domain == "" {
		h.log.Debug("initrollback: missing query parameter (domain)")
		h.newErrorResponse(c, http.StatusBadRequest, "missing query parameter (domain)")
		return
	}

	_, err := h.authService.GetAreaByDomain(domain)
	if err != nil {
		if err != errAreaNotFound {
			h.log.Errorf("initrollback: fatal error get area - %s, by domain - %s", err, domain)
			h.newErrorResponse(c, http.StatusInternalServerError, "failed get area by domain")
			return
		} else {
			h.newErrorResponse(c, http.StatusNotFound, "domain not found")
			return
		}
	}

	err = h.authService.DeleteSchema(domain)
	if err != nil {
		h.log.Errorf("initrollback: fatal error delete schema - %s", err)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	err = h.authService.DeleteArea(domain)
	if err != nil {
		h.log.Errorf("initrollback: fatal error delete area - %s", err)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

type response struct {
	Message string `json:"message"`
}

// Формирование respone
func (h *authHandler) newErrorResponse(c *gin.Context, statusCode int, message string) {
	c.AbortWithStatusJSON(statusCode, &response{
		Message: message,
	})
}

// Получение domain их контекста "domain"
func (h *authHandler) getDomain(c *gin.Context) string {
	domain, exists := c.Get("domain")
	if exists {
		domainStr, ok := domain.(string)
		if ok {
			return domainStr
		}
		h.log.Errorf("incorrect domain type - %s", domain)
	}
	return ""
}

// Устанавливает domain из host в контекст "domain"
func (h *authHandler) domainMiddleware(c *gin.Context) {
	h.log.Debug("handle domainMiddleware")

	host := c.Request.Host

	var shopDomain string
	if strings.Contains(host, ".") {
		arr := strings.Split(host, ".")
		if len(arr) == 2 {
			shopDomain = strings.Split(host, ".")[0]
		} else {
			h.log.Debug("domainMiddleware: host split error - len > 2")
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
	} else {
		h.log.Debug("domainMiddleware: domain is not defined (not contains `.`)")
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	_, err := h.authService.GetAreaByDomain(shopDomain)
	if err != nil {
		if err == errAreaNotFound {
			h.log.Debug("domainMiddleware: domain is not defined")
			c.AbortWithStatus(http.StatusNotFound)
			return
		} else {
			h.log.Errorf("domainMiddleware: failed GetAreaByDomain - %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	c.Set("domain", shopDomain)

	c.Next()
}

// (Внутренние сервисы) Устанавливает domain из host в контекст "domain"
func (h *authHandler) systemDomainMiddleware(c *gin.Context) {
	h.log.Debug("handle systemDomainMiddleware")

	domain := c.Query("domain")
	if domain == "" {
		h.log.Debug("systemDomainMiddleware: domain is not defined")
		h.newErrorResponse(c, http.StatusBadRequest, "missing query parameter (domain)")
		return
	}

	_, err := h.authService.GetAreaByDomain(domain)
	if err != nil {
		if err == errAreaNotFound {
			h.log.Debugf("systemDomainMiddleware: area with domain (%s) not found", domain)
			c.AbortWithStatus(http.StatusNotFound)
			return
		} else {
			h.log.Errorf("systemDomainMiddleware: failed GetAreaByDomain - %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	c.Set("domain", domain)

	c.Next()
}

// Авторизация и аутентификация (jwt)
func (h *authHandler) authWithRoleMiddleware(role []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.log.Debug("handle authWithRoleMiddleware")

		tokenString := c.Request.Header.Get("Authorization")

		if tokenString == "" {
			h.log.Debug("authmiddleware: authorization token not found")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(h.jwtSecret), nil
		})
		if err != nil {
			h.log.Debugf("authmiddleware: error jwt parse token: %v", err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if float64(time.Now().Unix()) > claims["exp"].(float64) {
				h.log.Debugf("authmiddleware: authorization token exp error (claims - %s)", claims)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			userId, ok := claims["sub"].(float64)
			if !ok {
				h.log.Debugf("authmiddleware: authorization token sub error - %s", tokenString)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			userRole, ok := claims["role"].(string)
			if !ok {
				h.log.Debugf("authmiddleware: authorization token role error - %s", tokenString)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			urlDomain := h.getDomain(c)
			tokenDomain, ok := claims["domain"].(string)
			if (!ok || (urlDomain != "" && tokenDomain != urlDomain)) && userRole != systemRole {
				h.log.Debugf("authmiddleware: url domain != token domain (urlDomain - %s, tokenDomain - %s) or tokenDomain domain failed", urlDomain, tokenDomain)
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			roleSuccess := false
			if len(role) == 0 {
				roleSuccess = true
			}

			for _, v := range role {
				if v == userRole {
					roleSuccess = true
					break
				}
			}

			if !roleSuccess {
				h.log.Debugf("authmiddleware: role forbidden (userRole - %s, role - %s)", userRole, role)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			c.Set("userId", userId)
			c.Set("userRole", userRole)

			c.Next()
		} else {
			h.log.Debugf("authmiddleware: invalid token")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
	}
}
