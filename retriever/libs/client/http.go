package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

const (
	SUCCESS_MESSAGE = "success"
	ERROR_MESSAGE   = "error"

	QUERY_DATA_INFO_URL  = "/getinfo"
	FETCH_CACHE_DATA_URL = "/cache-fetch"
	QUERY_CAPACITY_URL   = "/download_traffic_query"
	AUDIT_DATA_URL       = "/audit"
	QUERY_TEE_INFO       = "/query_information"
	NODE_STATUS_URL      = "/status"
)

type TeeReq struct {
	Cid         string `json:"cid,omitempty"`
	UserAcc     string `json:"user_eth_address,omitempty"`
	Key         []byte `json:"key,omitempty"`
	UserSign    []byte `json:"user_sign"`
	SupplierAcc string `json:"supplier_acc,omitempty"`
	OrderId     []byte `json:"oid,omitempty"`
	RequestId   string `json:"requestId,omitempty"`
	Nonce       []byte `json:"nonce,omitempty"`
	Data        []byte `json:"data,omitempty"`
}

type CacheRequest struct {
	Did       string `json:"did"`
	UserAddr  string `json:"user_addr"`
	RequestId string `json:"requestId"`
	ExtData   string `json:"extdata"`
	Sign      []byte `json:"sign"`
	Exp       int64  `json:"expiration"`
}

type TeeResp struct {
	Msg        string `json:"msg"`
	RemainCap  uint64 `json:"left_user_download_traffic"`
	EthAddress string `json:"eth_address"`
	Pubkey     []byte `json:"secp256k1_public_key"`
	UserAcc    string `json:"user_eth_address"`
	Data       any    `json:"data"`
}

type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

type FileMeta struct {
	Tid       string `json:"tid"`
	Did       string `json:"did"`
	Size      int64  `json:"size"`
	Key       string `json:"key"`
	Provider  string `json:"provider"`
	Timestamp string `json:"timestamp"`
}

type Cd2nNode struct {
	WorkAddr  string `json:"work_addr"`
	TeeAddr   string `json:"tee_addr"`
	TeePubkey []byte `json:"tee_pubkey"`
	EndPoint  string `json:"endpoint"`
	RedisAddr string `json:"redis_addr"`
	PoolId    string `json:"poolid"`
	IsGateway bool   `json:"is_gateway"`
	Status    `json:"status"`
}

type DiskStatus struct {
	UsedCacheSize  uint64  `json:"used_cache_size"`
	CacheItemNum   uint64  `json:"cache_item_num"`
	CacheUsage     float32 `json:"cache_usage"`
	UsedBufferSize uint64  `json:"used_buffer_size"`
	BufferItemNum  uint64  `json:"buffer_item_num"`
	BufferUsage    float32 `json:"buffer_usage"`
}

type DistStatus struct {
	Ongoing uint64 `json:"ongoing"`
	Done    uint64 `json:"done"`
	Expired uint64 `json:"expired"`
	FidNum  uint64 `json:"fid_num"`
}

type DownloadStatus struct {
	DlingNum uint64 `json:"dling_num"`
}

type RetrieveStatus struct {
	NTBR         uint64 `json:"ntbr"`
	RetrieveNum  uint64 `json:"retrieve_num"`
	RetrievedNum uint64 `json:"retrieved_num"`
}

type Status struct {
	DiskStatus     `json:"disk_status"`
	DistStatus     `json:"dist_status"`
	RetrieveStatus `json:"retrieve_status"`
	DownloadStatus `json:"download_status"`
}

func NewResponse(code int, msg string, data any) Response {
	return Response{
		Code: code,
		Msg:  msg,
		Data: data,
	}
}

func SendHttpRequest(method, url string, headers map[string]string, dataReader *bytes.Buffer) ([]byte, error) {
	req, err := http.NewRequest(method, url, dataReader)
	if err != nil {
		return nil, errors.Wrap(err, "send http request error")
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "send http request error")
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "send http request error")
	}

	if resp.StatusCode >= 400 {
		err = fmt.Errorf("bad request, status code %d, error %v", resp.StatusCode, string(bytes))
		return nil, errors.Wrap(err, "send http request error")
	}

	return bytes, nil
}

func AuditData(url, fpath, rpath string, req TeeReq) error {
	file, err := os.Open(fpath)
	if err != nil {
		return errors.Wrap(err, "audit data error")
	}
	defer file.Close()

	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	writer.WriteField("cid", req.Cid)
	writer.WriteField("user_acc", req.UserAcc)
	writer.WriteField("key", hex.EncodeToString(req.Key))
	writer.WriteField("nonce", hex.EncodeToString(req.Nonce))
	writer.WriteField("supplier_acc", req.SupplierAcc)
	writer.WriteField("request_id", req.RequestId)
	writer.WriteField("user_sign", hex.EncodeToString(req.UserSign))

	part, err := writer.CreateFormFile("file", filepath.Base(fpath))
	if err != nil {
		return errors.Wrap(err, "audit data error")
	}
	if _, err := io.Copy(part, file); err != nil {
		return errors.Wrap(err, "audit data error")
	}

	if err := writer.Close(); err != nil {
		return errors.Wrap(err, "audit data error")
	}
	headers := map[string]string{"Content-Type": writer.FormDataContentType()}
	data, err := SendHttpRequest(http.MethodPost, url, headers, &buffer)
	if err != nil {
		return errors.Wrap(err, "audit data error")
	}
	var teeResp TeeResp
	err = json.Unmarshal(data, &teeResp)
	if err != nil {
		return errors.Wrap(err, "audit data error")
	}
	if teeResp.Msg != SUCCESS_MESSAGE {
		return errors.Wrap(errors.New(fmt.Sprint(teeResp.Data)), "audit data error")
	}

	var content []byte
	err = json.Unmarshal(data, &TeeResp{Data: &content})
	if err != nil {
		return errors.Wrap(err, "audit data error")
	}
	if len(content) == 0 {
		return errors.Wrap(errors.New("empty response data"), "audit data error")
	}
	if err = os.WriteFile(rpath, content, 0755); err != nil {
		return errors.Wrap(err, "audit data error")
	}
	return nil
}

func QueryRemainCap(url, requester string) (uint64, error) {
	req := TeeReq{UserAcc: requester}
	jbytes, err := json.Marshal(req)
	if err != nil {
		return 0, errors.Wrap(err, "query user remain capacity error")
	}
	headers := map[string]string{"Content-Type": "application/json"}
	data, err := SendHttpRequest(http.MethodGet, url, headers, bytes.NewBuffer(jbytes))
	if err != nil {
		return 0, errors.Wrap(err, "query user remain capacity error")
	}
	var teeResp TeeResp

	if err = json.Unmarshal(data, &teeResp); err != nil {
		return 0, errors.Wrap(err, "query user remain capacity error")
	}
	return teeResp.RemainCap, nil
}

func RechargeCapacity(url, requester string, orderId [32]byte) error {
	req := TeeReq{
		UserAcc: requester,
		OrderId: orderId[:],
	}
	jbytes, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "recharge capacity error")
	}
	headers := map[string]string{"Content-Type": "application/json"}
	_, err = SendHttpRequest(http.MethodGet, url, headers, bytes.NewBuffer(jbytes))
	if err != nil {
		return errors.Wrap(err, "recharge capacity error")
	}
	return nil
}

func QueryTeeInfo(url string) (TeeResp, error) {
	data, err := SendHttpRequest(http.MethodGet, url, nil, bytes.NewBuffer(nil))
	if err != nil {
		return TeeResp{}, errors.Wrap(err, "query tee info error")
	}
	var resp TeeResp
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return TeeResp{}, errors.Wrap(err, "query user remain capacity error")
	}
	return resp, nil
}

func CheckCdnNodeAvailable(baseUrl string) (Cd2nNode, error) {
	var info Cd2nNode
	u, err := url.JoinPath(baseUrl, NODE_STATUS_URL)
	if err != nil {
		return info, errors.Wrap(err, "get CDN node status error")
	}
	data, err := SendHttpRequest(http.MethodGet, u, nil, bytes.NewBuffer(nil))
	if err != nil {
		return info, errors.Wrap(err, "get CDN node status error")
	}
	err = json.Unmarshal(data, &Response{Data: &info})
	log.Println("cd2n node from remote", info, err)
	if err != nil {
		return info, errors.Wrap(err, "get CDN node status error")
	}
	return info, nil
}
