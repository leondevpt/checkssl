package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/leondevpt/checkssl/pkg"
)

func main() {
	r := gin.Default()

	r.GET("/checkssl", pkg.CheckSslExpire)

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run() // listen and serve on 0.0.0.0:8080
}
