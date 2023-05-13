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
		auth.GET(validatePath, h.domainMiddleware, h.authMiddleware, h.validate)
	}
	user := router.Group("/user")
	{
		user.POST(userRolePath, h.domainMiddleware, h.authMiddleware, h.systemAndAdminRole, h.setRole)
		user.POST("", h.domainMiddleware, h.authMiddleware, h.systemAndAdminRole, h.createUser)
		user.PATCH("", h.domainMiddleware, h.authMiddleware, h.systemAndAdminRole, h.updateUser)
	}

	init := router.Group("/init")
	{
		init.POST("/start", h.authMiddleware, h.systemRole, h.initstart)
		init.POST("/rollback", h.authMiddleware, h.systemRole, h.initrollback)
	}
	system := router.Group("/system")
	{
		sestemAuthSub := system.Group("/auth")
		{
			sestemAuthSub.GET(validatePath, h.systemDomainMiddleware, h.authMiddleware, h.validate)
			sestemAuthSub.POST(loginPath, h.systemDomainMiddleware, h.login)
		}
	}
}

func (h *authHandler) login(c *gin.Context) {
	h.log.Debugf("login hadnler start")

	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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
	h.log.Debugf("login hadnler signup")

	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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
	h.log.Debugf("login hadnler validate")

	var body struct {
		Role []string `json:"role"`
	}

	if c.Bind(&body) != nil {
		h.newErrorResponse(c, http.StatusBadRequest, "failed to read body")
		return
	}

	tokenString := c.Request.Header.Get("X-System-Token")

	if tokenString == "" {
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
		h.log.Debugf("error jwt parse token: %v", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		_, ok := claims["sub"].(float64)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		irole, ok := claims["role"].(string)
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

		if !ok || !found {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		domain, err := h.getDomain(c)
		if err != nil && irole != "system" {
			h.newErrorResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		idomain, ok := claims["domain"].(string)
		if !ok || (domain != idomain && irole != "system") {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.JSON(http.StatusOK, gin.H{})
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

func (h *authHandler) setRole(c *gin.Context) {
	h.log.Debugf("login hadnler setRole")

	domain, err := h.getDomain(c)
	if err != nil {
		h.newErrorResponse(c, http.StatusBadRequest, err.Error())
		return
	}

	var body struct {
		Id   uint   `json:"id"`
		Role string `json:"role"`
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
	h.log.Debugf("login hadnler createUser")

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
		if err == errUserWithEmailAlreadyExists {
			h.newErrorResponse(c, http.StatusConflict, err.Error())
			return
		}
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}

func (h *authHandler) updateUser(c *gin.Context) {
	h.log.Debugf("login hadnler updateUser")

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
	h.log.Debugf("login hadnler initstart")

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
		h.authService.DeleteArea(domain)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func (h *authHandler) initrollback(c *gin.Context) {
	h.log.Debugf("login hadnler initrollback")

	domain := c.Query("domain")
	if domain == "" {
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

func (h *authHandler) getRole(c *gin.Context) (string, error) {
	role, exists := c.Get("userRole")
	if exists {
		roleStr, ok := role.(string)
		if ok {
			return roleStr, nil
		} else {
			return "", fmt.Errorf("incorrect role type - %v", role)
		}
	} else {
		return "", fmt.Errorf("role not found")
	}
}

func (h *authHandler) domainMiddleware(c *gin.Context) {
	h.log.Debugf("domainMiddleware start")

	host := c.Request.Host

	var shopDomain string
	if strings.Contains(host, ".") {
		arr := strings.Split(host, ".")
		if len(arr) == 2 {
			shopDomain = strings.Split(host, ".")[0]
		} else {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
	} else {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	_, err := h.authService.GetAreaByDomain(shopDomain)
	if err != nil {
		if err == errAreaNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return
		} else {
			h.log.Errorf("domainMiddleware: failed GetAreaByDomain - %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	fmt.Printf("request with domain - %s", shopDomain)
	c.Set("domain", shopDomain)

	c.Next()
}

func (h *authHandler) authMiddleware(c *gin.Context) {
	h.log.Debugf("authMiddleware start")

	tokenString := c.Request.Header.Get("Authorization")

	h.log.Debugf("authMiddleware Authorization Header - %s", tokenString)

	if tokenString == "" {
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
		h.log.Debugf("error jwt parse token: %v", err)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userId, ok := claims["sub"].(float64)
		if !ok {
			h.log.Debugf("authMiddleware Authorization Token Sub error - %s", tokenString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		userRole, ok := claims["role"].(string)
		if !ok {
			h.log.Debugf("authMiddleware Authorization Token UserRole error - %s", tokenString)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		domain, err := h.getDomain(c)
		if err != nil && userRole != "system" {
			h.log.Debugf("authMiddleware get domain err and userrole != system")
			h.newErrorResponse(c, http.StatusBadRequest, err.Error())
			return
		}

		idomain, ok := claims["domain"].(string)
		if userRole != "system" {
			if !ok || idomain != domain {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}
		}

		c.Set("userId", userId)
		c.Set("userRole", userRole)

		c.Next()
	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
}

func (h *authHandler) systemAndAdminRole(c *gin.Context) {
	h.log.Debugf("systemAndAdminRole start")

	role, err := h.getRole(c)
	if err != nil {
		h.log.Errorf("missing role in jwt - %v", role)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	if role == "system" || role == "admin" {
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
}

func (h *authHandler) systemRole(c *gin.Context) {
	h.log.Debugf("systemRole start")

	role, err := h.getRole(c)
	if err != nil {
		h.log.Errorf("missing role in jwt - %v", role)
		h.newErrorResponse(c, http.StatusInternalServerError, err.Error())
		return
	}

	if role == "system" {
		c.Next()
	} else {
		c.AbortWithStatus(http.StatusForbidden)
		return
	}
}

func (h *authHandler) systemDomainMiddleware(c *gin.Context) {
	h.log.Debugf("systemDomainMiddleware start")

	domain := c.Query("domain")
	if domain == "" {
		h.newErrorResponse(c, http.StatusBadRequest, "missing query parameter (domain)")
		return
	}

	_, err := h.authService.GetAreaByDomain(domain)
	if err != nil {
		if err == errAreaNotFound {
			c.AbortWithStatus(http.StatusNotFound)
			return
		} else {
			h.log.Errorf("domainMiddleware: failed GetAreaByDomain - %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
	}

	fmt.Printf("request with domain - %s", domain)
	c.Set("domain", domain)

	c.Next()
}
