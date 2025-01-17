package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/server/auth"
	"github.com/CD2N/CD2N/retriever/server/handles"
	"github.com/gin-gonic/gin"
)

func NewRouter() *gin.Engine {
	router := gin.New()
	router.Use(Cors())
	router.Use(TrimGetSuffix())
	router.Use(gin.CustomRecovery(func(c *gin.Context, err any) {
		errResp := client.NewResponse(http.StatusInternalServerError, "internal server error", err)
		c.JSON(http.StatusInternalServerError, errResp)
		c.Abort()
	}))
	//registerActivityRouter(router)
	return router
}

func TrimGetSuffix() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == http.MethodGet {
			req := c.Request.RequestURI
			idx := strings.LastIndex(req, "&")
			if idx > 0 {
				c.Request.RequestURI = req[0:idx]
			}
		}
		c.Next()
	}
}

func HealthCheck(c *gin.Context) {
	c.JSON(200, 0)
}

func DebugHandle(c *gin.Context) {
	c.JSON(200, "ok")
}

func TokenVerify(c *gin.Context) {
	if strings.Contains(c.Request.RequestURI, "/gentoken") {
		c.Next()
		return
	}
	clams, err := parseToken(c)
	if err != nil {
		resp := client.NewResponse(http.StatusForbidden, "Invalid token", err.Error())
		c.JSON(resp.Code, resp)
		c.Abort()
		return
	}
	c.Set("user", clams.User)
	c.Next()
}

func parseToken(c *gin.Context) (*auth.CustomClaims, error) {
	token := strings.TrimPrefix(c.GetHeader("token"), "Bearer ")
	if token == "" {
		return nil, errors.New("invalid token")
	}

	clams, err := auth.Jwth().ParseToken(token)
	if err != nil {
		return nil, err
	}
	return clams, nil
}

func Cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type,AccessToken,X-CSRF-Token, Authorization, Token, token")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PATCH, PUT")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Content-Type")
		c.Header("Access-Control-Allow-Credentials", "true")

		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
	}
}

func RegisterHandles(router *gin.Engine, h *handles.ServerHandle) {

	router.GET("/status", h.GetNodeInfo)
	router.GET("/capacity/:addr", h.QueryCacheCap)
	router.GET("/querydata/:did", h.QueryData)
	router.POST("/cache-fetch", h.FetchCacheData)
	router.POST("/provide", h.ProvideData)
	if !config.GetConfig().LaunchGateway {
		return
	}
	router.POST("/claim", h.ClaimFile)
	router.GET("/fetch", h.FetchFile)

	gateway := router.Group("/gateway")
	gateway.Use(TokenVerify)
	gateway.POST("/gentoken", h.GenToken)
	gateway.GET("/getinfo/:segment", h.GetDataInfo)
	gateway.HEAD("/download/:fid/:segment", h.DownloadUserFile)
	gateway.GET("/download/:fid", h.DownloadUserFile)
	gateway.GET("/download/:fid/:segment", h.DownloadUserFile)
	gateway.POST("/upload/file", h.UploadUserFile)
	gateway.POST("/part-upload", h.RequestPartsUpload)
	gateway.POST("/upload/part", h.UploadFileParts)

}
