package handles

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/node"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

func (h *ServerHandle) DownloadUserFile(c *gin.Context) {
	var targetPath string
	if !config.GetConfig().DisableLocalSvc {
		targetPath = c.Param("target")
	}
	fid := c.Param("fid")
	if fid == "" {
		c.JSON(http.StatusBadRequest,
			tsproto.NewResponse(http.StatusBadRequest, "download file error", "bad file id"))
		return
	}
	segment := c.Param("segment")
	key := segment
	if key == "" {
		key = fid
	}
	err := h.gateway.WaitFileCache(key, time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
		return
	}

	defer h.gateway.ReleaseCacheTask(key)

	item := h.gateway.FileCacher.GetData(key)
	if item.Value != "" {
		fname, fpath := buffer.SplitNamePath(item.Value)
		if fname == "" || fname == buffer.UNNAMED_FILENAME {
			if fname, err = h.GetFileName(fid); err != nil {
				logger.GetLogger(config.LOG_GATEWAY).Infof("get file %s name error %v", key, err)
				fname = key
			}
		}
		logger.GetLogger(config.LOG_GATEWAY).Infof("get file %s from local disk cache", key)
		err = ServeFile(c, fname, fpath, targetPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError,
				tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
		}
		return
	}
	cessCli, err := h.gateway.GetCessClient()
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
		return
	}
	fmeta, err := cessCli.QueryFileMetadata(fid, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
		return
	}
	var (
		fragPaths []string
		segPaths  []string
	)

	for _, seg := range fmeta.SegmentList {
		sid := string(seg.Hash[:])
		if key == segment && sid != key {
			continue
		}

		item := h.gateway.FileCacher.GetData(string(seg.Hash[:]))
		if item.Value != "" {
			segPaths = append(segPaths, item.Value)
			continue
		}

		fragments := ParseDataIds(seg)
		fragPaths, fragments = h.GetDataFromDiskBuffer(fragments...) //retrieve from local buffer
		logger.GetLogger(config.LOG_GATEWAY).Infof("get fragments from local disk buffer:%v", len(fragPaths))
		if len(fragPaths) < config.FRAGMENTS_NUM { //retrieve from L2 node, triggered when cache miss, low efficiency
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
			defer cancel()
			task := node.NewCesRetrieveTask(cessCli, "", fid, sid, fragments)
			paths, err := h.retr.RetrieveData(ctx, task)
			if err != nil {
				c.JSON(http.StatusInternalServerError,
					tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
				return
			}
			fragPaths = append(fragPaths, paths...)
			logger.GetLogger(config.LOG_GATEWAY).Infof("get fragments from miner pool(bridged via L2 cachers):%v", len(paths))
		}

		//deal with fragments
		if len(fragPaths) < config.FRAGMENTS_NUM {
			c.JSON(http.StatusInternalServerError,
				tsproto.NewResponse(http.StatusInternalServerError, "download file error", "insufficient cached fragments"))
			return
		}

		segPath, err := h.gateway.CompositeSegment(sid, fragPaths)
		if err != nil {
			c.JSON(http.StatusInternalServerError,
				tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
			return
		}
		segPaths = append(segPaths, segPath)
	}
	if len(segPaths) != len(fmeta.SegmentList) || len(segPaths) <= 0 {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", "no valid segments were retrieved"))
		return
	}
	fpath, err := h.gateway.CombineFileIntoCache(fid, fmeta.FileSize.Int64(), segPaths)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
		return
	}

	h.gateway.ReleaseCacheTask(key) //allows repeated calls to minimize key usage
	logger.GetLogger(config.LOG_GATEWAY).Infof("get file %s from CD2N network", fid)

	err = ServeFile(c, string(fmeta.Owner[0].FileName), fpath, targetPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			tsproto.NewResponse(http.StatusInternalServerError, "download file error", err.Error()))
	}

}

func (h *ServerHandle) GetDataFromDiskBuffer(dids ...string) ([]string, []string) {
	var (
		res  []string
		rems []string
	)
	for _, did := range dids {
		item := h.buffer.GetData(did)
		if item.Value != "" {
			res = append(res, item.Value)
		} else {
			rems = append(rems, did)
		}
		if len(res) >= config.FRAGMENTS_NUM {
			return res, rems
		}
	}
	return res, rems
}

func ParseFileRange(frange string) (int64, int64, error) {
	ranges := strings.Split(frange, "=")
	if len(ranges) != 2 || ranges[0] != "bytes" {
		return 0, 0, errors.Wrap(errors.New("invalid range"), "parse file range error")
	}
	parts := strings.Split(ranges[1], "-")
	if len(parts) != 2 {
		return 0, 0, errors.Wrap(errors.New("invalid range"), "parse file range error")
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, errors.Wrap(err, "parse file range error")
	}
	var end int64
	if parts[1] != "" {
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, errors.Wrap(err, "parse file range error")
		}
	}
	return start, end, nil
}

func ServeFile(c *gin.Context, name, fpath, target string) error {
	if target != "" {
		return errors.Wrap(utils.CopyFile(fpath, target), "serve file error")
	}
	fileRange := c.Request.Header.Get("Range")
	if fileRange != "" {
		logger.GetLogger(config.LOG_GATEWAY).Infof("serve file %s for range request, range: %s", fpath, fileRange)
		err := RangeRequest(c, fileRange, name, fpath)
		return errors.Wrap(err, "serve file error")
	}
	logger.GetLogger(config.LOG_GATEWAY).Infof("serve file %s", fpath)
	c.FileAttachment(fpath, name)
	//c.File(fpath)
	return nil
}

func RangeRequest(c *gin.Context, frange, name, fpath string) error {
	file, err := os.Open(fpath)
	if err != nil {
		return errors.Wrap(err, "file range request error")
	}
	defer file.Close()
	start, end, err := ParseFileRange(frange)
	if err != nil {
		return errors.Wrap(err, "file range request error")
	}
	stat, err := file.Stat()
	if err != nil {
		return errors.Wrap(err, "file range request error")
	}
	if end <= 0 || end > stat.Size() {
		end = stat.Size()
	}
	mime := make([]byte, 512)
	_, err = file.Read(mime)
	if err != nil {
		return errors.Wrap(err, "file range request error")
	}
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, stat.Size()))
	c.Header("Content-Length", strconv.FormatInt(end-start, 10))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", name))
	c.Header("Content-type", http.DetectContentType(mime))
	c.Status(http.StatusPartialContent)
	file.Seek(start, io.SeekStart)
	io.CopyN(c.Writer, file, end-start)
	return nil
}

func ParseDataIds(segment chain.SegmentInfo) []string {
	dids := make([]string, 0, len(segment.FragmentList))
	for _, fragment := range segment.FragmentList {
		dids = append(dids, string(fragment.Hash[:]))
	}
	return dids
}

func (h *ServerHandle) GetFileName(fid string) (string, error) {
	var fname string
	cli, err := h.gateway.GetCessClient()
	if err != nil {
		return fname, errors.Wrap(err, "get file name error")
	}
	meta, err := cli.QueryFileMetadata(fid, 0)
	if err == nil {
		for _, owner := range meta.Owner {
			fname = string(owner.FileName)
			if fname != "" {
				return fname, nil
			}
		}
	}
	dealmap, err := cli.QueryDealMap(fid, 0)
	if err != nil {
		return fname, errors.Wrap(err, "get file name error")
	}
	fname = string(dealmap.User.FileName)
	return fname, nil
}
