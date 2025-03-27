package handles

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/retriever/server/auth"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (h *ServerHandle) UploadUserFileTemp(c *gin.Context) {
	acc := c.PostForm("account")
	pubkey, err := utils.ParsingPublickey(acc)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	territory := c.PostForm("territory")
	if territory == "" {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", "bad file params"))
		return
	}
	async := c.PostForm("async") == "true"
	noProxy := c.PostForm("noProxy") == "true"

	file, err := c.FormFile("file")

	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.uploadFile(c, src, pubkey, territory, file.Filename, async, noProxy)
}

func (h *ServerHandle) UploadUserFile(c *gin.Context) {
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", "bad user info"))
		return
	}
	territory := c.PostForm("territory")
	if territory == "" {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", "bad file params"))
		return
	}
	async := c.PostForm("async") == "true"
	noProxy := c.PostForm("noProxy") == "true"

	file, err := c.FormFile("file")

	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload user file error", err.Error()))
		return
	}
	h.uploadFile(c, src, user.Account, territory, file.Filename, async, noProxy)
}

func (h *ServerHandle) uploadFile(c *gin.Context, file io.Reader, acc []byte, territory, filename string, async, noProxy bool) {
	tmpName := hex.EncodeToString(utils.CalcSha256Hash(acc, []byte(territory+filename)))
	fpath, err := h.buffer.NewBufPath(tmpName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload file error", err.Error()))
		return
	}
	err = h.SaveDataToBuf(file, fpath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload  file error", err.Error()))
		return
	}
	finfo, err := h.gateway.ProcessFile(h.buffer, filename, fpath, territory, acc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload file error", err.Error()))
		return
	}

	cachePath, err := h.gateway.FileCacher.NewBufPath(finfo.Fid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload file error", err.Error()))
		return
	}
	err = os.Rename(fpath, cachePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload file error", err.Error()))
		return
	}
	h.gateway.FileCacher.AddData(finfo.Fid, buffer.CatNamePath(filename, cachePath))
	if !async {
		err = h.gateway.ProvideFile(context.Background(), time.Hour, finfo, false)
		if err != nil {
			c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "upload file error", err.Error()))
			return
		}
		c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", finfo.Fid))
		return
	}
	client.PutData(h.partRecord, config.DB_FINFO_PREFIX+finfo.Fid, task.AsyncFinfoBox{Info: finfo, NonProxy: noProxy})
	c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", finfo))
}

func (h *ServerHandle) UploadFileParts(c *gin.Context) {
	partId := c.PostForm("partid")
	shadowHash := c.PostForm("shadowhash")
	async := c.PostForm("async") == "true"
	noProxy := c.PostForm("noProxy") == "true"
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	if partId == "" || shadowHash == "" {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", "bad params"))
		return
	}
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "parts upload error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "parts upload error", "bad user info"))
		return
	}
	idx, err := strconv.Atoi(partId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	fkey := hex.EncodeToString(utils.CalcSha256Hash(user.Account, []byte(shadowHash), []byte(partId)))
	fpath, err := h.buffer.NewBufPath(hex.EncodeToString(user.Account), shadowHash, fkey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	err = h.SaveFileToBuf(file, fpath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	h.buffer.AddData(fkey, fpath)
	v, ok := h.filepartMap.Load(shadowHash)
	if !ok {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", "no parts record"))
		return
	}
	lock, ok := v.(*sync.Mutex)
	if !ok {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", "parse key locker error"))
		return
	}
	lock.Lock()
	defer lock.Unlock()
	var partsInfo PartsInfo
	err = client.GetData(h.partRecord, config.DB_FILEPART_PREFIX+shadowHash, &partsInfo)
	if err != nil {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	if idx >= len(partsInfo.Parts) || idx < 0 {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "parts upload error", "bad file index"))
		return
	}
	if !bytes.Equal(partsInfo.Owner, user.Account) {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "parts upload error", "file owner mismatch"))
		return
	}
	partsInfo.Parts[idx] = file.Filename
	partsInfo.PartsCount++
	if partsInfo.PartsCount < partsInfo.TotalParts {
		err = client.PutData(h.partRecord, config.DB_FILEPART_PREFIX+shadowHash, partsInfo)
		if err != nil {
			h.buffer.RemoveData(fpath)
			c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
			return
		}
		c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", partId))
		return
	}
	//combine files
	defer client.DeleteData(h.partRecord, config.DB_FILEPART_PREFIX+shadowHash)
	cfile, err := h.CombineFileParts(partsInfo)
	if err != nil {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "parts upload error", err.Error()))
		return
	}
	f, err := os.Open(cfile)
	if err != nil {
		h.buffer.RemoveData(fpath)
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "parts upload error", err.Error()))
		return
	}
	fname := partsInfo.FileName
	if partsInfo.Archive != "" && partsInfo.DirName != "" {
		fname = partsInfo.DirName
	}
	h.uploadFile(c, f, user.Account, partsInfo.Territory, fname, async, noProxy)
}

func (h *ServerHandle) RequestPartsUpload(c *gin.Context) {
	var (
		partsInfo PartsInfo
		err       error
	)

	if err := c.BindJSON(&partsInfo); err != nil {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "request parts upload error", err.Error()))
		return
	}
	if partsInfo.FileName == "" || partsInfo.ShadowHash == "" || partsInfo.Territory == "" ||
		partsInfo.TotalParts <= 0 || partsInfo.TotalSize <= 0 {
		c.JSON(http.StatusInternalServerError, client.NewResponse(http.StatusInternalServerError, "request parts upload error", "bad request params"))
		return
	}
	value, ok := c.Get("user")
	if !ok {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "request parts upload error", "bad user info"))
		return
	}
	user, ok := value.(auth.UserInfo)
	if !ok || user.Account == nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "request parts upload error", "bad user info"))
		return
	}
	if _, ok := h.filepartMap.LoadOrStore(partsInfo.ShadowHash, &sync.Mutex{}); ok {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "request parts upload error", "file part is uploading"))
		return
	}
	partsInfo.Owner = user.Account
	partsInfo.UpdateDate = time.Now()
	partsInfo.Parts = make([]string, partsInfo.TotalParts)
	err = client.PutData(h.partRecord, config.DB_FILEPART_PREFIX+partsInfo.ShadowHash, partsInfo)
	if err != nil {
		c.JSON(http.StatusBadRequest, client.NewResponse(http.StatusBadRequest, "upload user file error", err.Error()))
		return
	}
	c.JSON(http.StatusOK, client.NewResponse(http.StatusOK, "success", nil))
}

func (h *ServerHandle) CombineFileParts(info PartsInfo) (string, error) {
	var files []string = make([]string, 0, info.TotalParts)

	tmpName := hex.EncodeToString(utils.CalcSha256Hash(info.Owner, []byte(info.Territory+info.DirName)))
	fpath, err := h.buffer.NewBufPath(tmpName)
	if err != nil {
		return "", errors.Wrap(err, "combine file parts error")
	}

	for idx := 0; idx < info.TotalParts; idx++ {
		fkey := hex.EncodeToString(utils.CalcSha256Hash(info.Owner, []byte(info.ShadowHash), []byte(fmt.Sprint(idx))))
		subPath, err := h.buffer.NewBufPath(hex.EncodeToString(info.Owner), info.ShadowHash, fkey)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
		files = append(files, subPath)
	}
	defer func() {
		for _, f := range files {
			h.buffer.RemoveData(f)
		}
	}()
	if info.Archive != "" && info.DirName != "" {
		ar, err := utils.NewArchiver(info.Archive)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}

		err = ar.Archive(files, fpath)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
		h.buffer.AddData(tmpName, fpath)
		return fpath, nil
	}
	file, err := os.Create(fpath)
	if err != nil {
		return "", errors.Wrap(err, "combine file parts error")
	}
	defer file.Close()
	for _, subfile := range files {
		data, err := os.ReadFile(subfile)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
		_, err = file.Write(data)
		if err != nil {
			return "", errors.Wrap(err, "combine file parts error")
		}
	}
	h.buffer.AddData(tmpName, fpath)
	return fpath, nil
}

func (h *ServerHandle) AsyncUploadFiles(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute * 15)
	for {
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
		if err := client.DbIterator(h.partRecord, func(b []byte) error {
			key := string(b)
			if !strings.Contains(key, config.DB_FINFO_PREFIX) {
				return nil
			}
			var box task.AsyncFinfoBox
			if err := client.GetData(h.partRecord, key, &box); err != nil {
				logger.GetLogger(config.LOG_GATEWAY).Info("get file info box from db error ", err)
				return nil
			}

			if box.NonProxy {
				cli, err := h.gateway.GetCessClient()
				if err != nil {
					logger.GetLogger(config.LOG_GATEWAY).Info("provide file async error ", err)
					return nil
				}
				_, err = cli.QueryDealMap(box.Info.Fid, 0)
				if err != nil {
					logger.GetLogger(config.LOG_GATEWAY).Info("provide file async error ", err)
					return nil
				}
				if err := h.gateway.ProvideFile(context.Background(), time.Hour, box.Info, true); err != nil {
					logger.GetLogger(config.LOG_GATEWAY).Info("provide file async error ", err)
					return nil
				}
				client.DeleteData(h.partRecord, key)
				return nil
			}

			if err := h.gateway.ProvideFile(context.Background(), time.Hour, box.Info, false); err != nil {
				logger.GetLogger(config.LOG_GATEWAY).Info("provide file async error ", err)
			}
			client.DeleteData(h.partRecord, key)
			return nil
		}); err != nil {
			logger.GetLogger(config.LOG_GATEWAY).Info("traverse the file async upload request list error", err)
		}
	}
}
