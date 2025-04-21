package handles

import (
	"context"
	"net/http"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/gateway"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/gin-gonic/gin"
)

func (h *ServerHandle) ClaimFile(c *gin.Context) {
	var req gateway.FileRequest
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "claim file error", "bad request params"))
		return
	}
	// TODO: Node Filter

	resp, err := h.gateway.ClaimFile(context.Background(), req)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "claim file error", err.Error()))
		return
	}
	logger.GetLogger(config.LOG_PROVIDER).Infof("L2 Node %s claim fragments from file %s  success.", resp.Token, resp.Fid)
	c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", resp))
}

func (h *ServerHandle) FetchFile(c *gin.Context) {
	fid := c.Query("fid")
	fragment := c.Query("fragment")
	token := c.Request.Header.Get("token")
	if fid == "" || fragment == "" || token == "" {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "fetch file error", "bad request params"))
		return
	}
	fpath, err := h.gateway.FetchFile(context.Background(), fid, fragment, token)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "fetch file error", err.Error()))
		return
	}
	cid, err := h.node.GetDataCid(fragment)
	if err != nil || cid == "" {
		_, err = h.node.CalcDataCid(fragment, fpath)
		if err != nil {
			c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusInternalServerError, "fetch file error", err.Error()))
			return
		}
	}
	logger.GetLogger(config.LOG_PROVIDER).Infof("L2 Node %s fetch fragment %s from file %s  success.", token, fragment, fid)
	c.File(fpath)
}
