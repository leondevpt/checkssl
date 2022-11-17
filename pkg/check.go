package pkg

import (
	"crypto/tls"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Response struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data interface{} `json:"data,omitempty"`
}

type SslDate struct {
	StartDate string `json:"startDate"`
	EndDate   string `json:"endDate"`
}

func CheckSslExpire(c *gin.Context) {
	domainName := c.Query("domain")

	resp := Response{Code: 0, Msg: "Ok"}

	if domainName == "" {
		log.Printf("invalid domain")
		resp.Code = 10001
		resp.Msg = "域名不能为空"
		c.AbortWithStatusJSON(http.StatusBadRequest, resp)
		return
	}
	c.JSON(http.StatusOK, sslcheck(domainName))
}

func sslcheck(domainName string) Response {
	resp := Response{Code: 0, Msg: "Ok"}

	if !strings.HasSuffix(domainName, ":443") {
		domainName = domainName + ":443"
	}
	if strings.HasPrefix(domainName, "https://") {
		domainName = strings.SplitN(domainName, "https://", 2)[1]
	}

	conn, err := tls.Dial("tcp", domainName, nil)

	if err != nil {
		resp.Code = 10002
		resp.Msg = err.Error()
		return resp
	}

	before := conn.ConnectionState().PeerCertificates[0].NotBefore
	after := conn.ConnectionState().PeerCertificates[0].NotAfter

	layout := "2006-01-02 15:04:05"

	resp.Data = SslDate{
		StartDate: before.Format(layout),
		EndDate:   after.Format(layout),
	}

	return resp
}
