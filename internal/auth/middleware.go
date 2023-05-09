package auth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func DomainMiddleware(c *gin.Context) {
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

	fmt.Printf("request with domain - %s", shopDomain)
	c.Set("domain", shopDomain)

	c.Next()
}
