package handles

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (h *ServerHandle) QueryData(c *gin.Context) {
	did := c.Param("did")
	if did == "" {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "query data error", "bad query params"))
		return
	}
	cid, err := h.node.GetDataCid(did)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "query data error", "cid not found"))
		return
	}
	c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", cid != ""))
}

func (h *ServerHandle) FetchCacheData(c *gin.Context) {

	var req client.CacheRequest
	err := c.BindJSON(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "fetch data error", err.Error()))
		return
	}
	if time.Duration(req.Exp) <= 0 || time.Duration(req.Exp) > time.Minute {
		req.Exp = int64(time.Second * 12)
	}
	cid, err := h.node.GetDataCid(req.Did)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "fetch data error", "cid not found"))
		return
	}

	u, _ := url.JoinPath(h.teeEndpoint, client.AUDIT_DATA_URL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Exp))
	defer cancel()

	var rpath string
	tid, err := h.node.RetrieveData(ctx, req.Did, req.UserAddr, req.RequestId, req.ExtData, time.Duration(req.Exp), req.Sign)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "fetch data error", err.Error()))
		return
	}
	task, err := h.node.GetRetrieveTask(ctx, tid)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "fetch data error", err.Error()))
		return
	}
	rpath, err = h.buffer.NewBufPath(cid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
		return
	}

	var fpath string

	if task.Pubkey != nil {
		tidBytes, _ := hex.DecodeString(tid)
		if err = client.AuditData(u, task.DataPath, rpath, client.TeeReq{
			Cid:         cid,
			UserAcc:     utils.Remove0x(req.UserAddr),
			Key:         task.Pubkey,
			Nonce:       tidBytes,
			UserSign:    req.Sign,
			RequestId:   req.RequestId,
			SupplierAcc: task.Provider,
		}); err != nil {
			c.JSON(http.StatusInternalServerError,
				client.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
			return
		}
		fpath = rpath
		h.buffer.RemoveData(task.DataPath)
	} else { //The L2 nodes provide unencrypted data
		fpath = task.DataPath
		h.buffer.RemoveData(rpath)
	}
	if info, err := os.Stat(fpath); err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "fetch data error", err.Error()))
		return
	} else {
		if !strings.HasPrefix(req.UserAddr, "0x") {
			req.UserAddr = "0x" + req.UserAddr
		}
		h.gateway.UpdateNodesLedger(req.UserAddr, info.Size())
	}
	c.File(fpath)
	h.buffer.AddData(cid, fpath)
}

func (h *ServerHandle) ProvideData(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "provide data error", err.Error()))
		return
	}
	if file.Size <= 0 {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "provide data error", "invalid data"))
		return
	}
	metaStr := c.PostForm("metadata")
	if metaStr == "" {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "provide data error", "bad metadata"))
		return
	}
	var meta client.FileMeta
	err = json.Unmarshal([]byte(metaStr), &meta)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "provide data error", err.Error()))
		return
	}
	if meta.Did == "" {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "provide data error", "bad metadata"))
		return
	}
	fpath, err := h.buffer.NewBufPath(meta.Did)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "provide data error", err.Error()))
		return
	}
	err = h.SaveFileToBuf(file, fpath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "provide data error", err.Error()))
		return
	}
	h.buffer.AddData(meta.Did, fpath)
	defer func() {
		if err != nil {
			h.buffer.RemoveData(fpath)
		}
	}()
	pubkey, err := hex.DecodeString(meta.Key)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "provide data error", err.Error()))
		return
	}
	err = h.node.ReceiveData(context.Background(), meta.Tid, meta.Provider, fpath, pubkey)
	if err != nil {
		logger.GetLogger(config.LOG_RETRIEVE).Error(err)
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "provide data error", err.Error()))
		return
	}
}

func (h *ServerHandle) QueryCacheCap(c *gin.Context) {
	user := c.Param("addr")
	if user == "" {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "check cache order error", "bad request params"))
		return
	}
	u, _ := url.JoinPath(h.teeEndpoint, "download_traffic_query")
	log.Println(u)
	ccap, err := client.QueryRemainCap(u, user)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "query cache cap", err.Error()))
		return
	}
	c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", ccap))
}

// func (h *ServerHandle) CheckCacheOrder(c *gin.Context) {
// 	var req client.TeeReq
// 	err := c.BindJSON(&req)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "check cache order error", "bad request params"))
// 		return
// 	}
// 	u, _ := url.JoinPath(h.teeEndpoint, "order", "recharge")
// 	if err = client.RechargeCapacity(u, req.UserAcc, [32]byte(req.OrderId)); err != nil {
// 		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "check cache order error", err.Error()))
// 		return
// 	}
// 	c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", nil))
// }

func (h *ServerHandle) SaveFileToBuf(file *multipart.FileHeader, fpath string) error {
	src, err := file.Open()
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	defer src.Close()

	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	err = f.Sync()
	return errors.Wrap(err, "cache file error")
}

func (h *ServerHandle) SaveDataToBuf(src io.Reader, fpath string) error {

	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "cache file error")
	}
	defer f.Close()
	_, err = io.Copy(f, src)
	return errors.Wrap(err, "cache file error")
}
