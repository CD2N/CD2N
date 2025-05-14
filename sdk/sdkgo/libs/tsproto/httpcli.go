package tsproto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// Retriever API URL

const (
	FRAGMENT_SIZE   = 8 * 1024 * 1024
	NODE_STATUS_URL = "/status"
	CLAIM_DATA_URL  = "/claim"
	PUSH_DATA_URL   = "/provide"
	FETCH_DATA_URL  = "/fetch"
)

// Justicar API URL
const (
	SUCCESS_MESSAGE = "success"
	ERROR_MESSAGE   = "error"

	QUERY_DATA_INFO_URL  = "/getinfo"
	FETCH_CACHE_DATA_URL = "/cache-fetch"
	QUERY_CAPACITY_URL   = "/download_traffic_query"
	AUDIT_DATA_URL       = "/audit"
	QUERY_TEE_INFO       = "/query_information"
)

type StorageNode struct {
	Account  string `json:"account"`
	Endpoint string `json:"endpoint"`
}

type FileRequest struct {
	Pubkey       []byte        `json:"pubkey"`
	Fid          string        `json:"fid"`
	Timestamp    string        `json:"timestamp"`
	StorageNodes []StorageNode `json:"storage_nodes"`
	Sign         string        `json:"sign"`
}

type FileResponse struct {
	Fid       string   `json:"fid"`
	Fragments []string `json:"fragments"`
	Token     string   `json:"token"`
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
	WorkAddr           string   `json:"work_addr"`
	TeeAddr            string   `json:"tee_addr"`
	TeePubkey          []byte   `json:"tee_pubkey"`
	EndPoint           string   `json:"endpoint"`
	RedisAddr          string   `json:"redis_addr"`
	PoolId             string   `json:"poolid"`
	IsGateway          bool     `json:"is_gateway"`
	ActiveStorageNodes []string `json:"active_storage_nodes"`
	Status             `json:"status"`
}

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
	Retried uint64 `json:"retried"`
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

type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

func NewResponse(code int, msg string, data any) Response {
	return Response{
		Code: code,
		Msg:  msg,
		Data: data,
	}
}

func (r Response) Status() int {
	return r.Code
}

func (r Response) Error() error {
	if r.Code >= 400 {
		return errors.New(r.Msg)
	}
	return nil
}

func (r Response) Result() any {
	return r.Data
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
		err = fmt.Errorf("error: %s", string(bytes))
		return nil, errors.Wrap(err, "send http request error")
	}

	return bytes, nil
}

func PushFile(url, fpath string, metaDatas map[string][]byte) ([]byte, error) {
	file, err := os.Open(fpath)
	if err != nil {
		return nil, errors.Wrap(err, "upload file error")
	}
	defer file.Close()

	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	for key, value := range metaDatas {
		if err := writer.WriteField(key, string(value)); err != nil {
			return nil, errors.Wrap(err, "upload file error")
		}
	}

	part, err := writer.CreateFormFile("file", filepath.Base(fpath))
	if err != nil {
		return nil, errors.Wrap(err, "upload file error")
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, errors.Wrap(err, "upload file error")
	}

	if err := writer.Close(); err != nil {
		return nil, errors.Wrap(err, "upload file error")
	}
	headers := map[string]string{"Content-Type": writer.FormDataContentType()}
	resp, err := SendHttpRequest("POST", url, headers, &buffer)
	if err != nil {
		return nil, errors.Wrap(err, "upload file error")
	}
	return resp, nil
}

func ClaimFile(url string, req FileRequest) (FileResponse, error) {
	var (
		buffer bytes.Buffer
		res    FileResponse
		pld    Response
	)

	jbytes, err := json.Marshal(req)
	if err != nil {
		return res, errors.Wrap(err, "claim file from gateway error")
	}

	if _, err := buffer.Write(jbytes); err != nil {
		return res, errors.Wrap(err, "claim file from gateway error")
	}

	headers := map[string]string{"Content-Type": "application/json"}
	resp, err := SendHttpRequest(http.MethodPost, url, headers, &buffer)
	if err != nil {
		return res, errors.Wrap(err, "claim file from gateway error")
	}

	if err = json.Unmarshal(resp, &pld); err != nil {
		return res, errors.Wrap(err, "claim file from gateway error")
	}
	if pld.Code != 200 {
		err = fmt.Errorf("response message:%s, data: %v", pld.Msg, pld.Data)
		return res, errors.Wrap(err, "claim file from gateway error")
	}
	if err = json.Unmarshal(resp, &Response{Data: &res}); err != nil {
		return res, errors.Wrap(err, "claim file from gateway error")
	}
	if res.Token == "" {
		err = errors.New("bad token response")
		return res, errors.Wrap(err, "claim file from gateway error")
	}
	return res, nil
}

func FetchFile(gatewayUrl, token, fid, did string) ([]byte, error) {
	params := url.Values{}
	params.Add("fragment", did)
	params.Add("fid", fid)
	u := gatewayUrl + "?" + params.Encode()
	headers := map[string]string{"token": token}
	resp, err := SendHttpRequest(http.MethodGet, u, headers, bytes.NewBuffer(nil))
	if err != nil {
		return nil, errors.Wrap(err, "fetch file from gateway error")
	}
	return resp, nil
}

func PushFileToStorageNode(url, acc, message, sign, fid, fragment, path string) error {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	formFile, err := writer.CreateFormFile("file", fragment)
	if err != nil {
		return errors.Wrap(err, "push file to storage node error")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.Wrap(err, "push file to storage node error")
	}
	defer file.Close()

	if _, err = io.Copy(formFile, file); err != nil {
		return errors.Wrap(err, "push file to storage node error")
	}

	if err = writer.Close(); err != nil {
		return errors.Wrap(err, "push file to storage node error")
	}

	headers := map[string]string{
		"Fid":          fid,
		"Fragment":     fragment,
		"Account":      acc,
		"Message":      message,
		"Signature":    sign,
		"Content-Type": writer.FormDataContentType(),
	}
	data, err := SendHttpRequest(http.MethodPut, url, headers, body)
	if err != nil {
		return errors.Wrap(err, "push file to storage node error")
	}
	var res Response
	err = json.Unmarshal(data, &res)
	if err != nil {
		return errors.Wrap(err, "push file to storage node error")
	}
	if res.Code != 200 {
		err = errors.New(res.Msg)
		return errors.Wrap(err, "push file to storage node error")
	}
	return nil
}

func GetFileFromStorageNode(url, acc, message, sign, fid, fragment, path string) error {

	headers := map[string]string{
		"Fid":          fid,
		"Fragment":     fragment,
		"Account":      acc,
		"Message":      message,
		"Signature":    sign,
		"Content-Type": "application/json",
	}
	data, err := SendHttpRequest(http.MethodGet, url, headers, bytes.NewBuffer(nil))
	if err != nil {
		return errors.Wrap(err, "get file from storage node error")
	}
	file, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "get file from storage node error")
	}
	defer file.Close()
	n, err := file.Write(data)
	if err != nil {
		return errors.Wrap(err, "get file from storage node error")
	}
	if n != FRAGMENT_SIZE {
		err = errors.New("bad data size")
		return errors.Wrap(err, "get file from storage node error")
	}
	return nil
}

func CheckStorageNodeAvailable(baseUrl string) error {
	u, err := url.JoinPath(baseUrl, NODE_STATUS_URL)
	if err != nil {
		return errors.Wrap(err, "get storage node status error")
	}
	_, err = SendHttpRequest(http.MethodGet, u, nil, bytes.NewBuffer(nil))
	if err != nil {
		return errors.Wrap(err, "get storage node status error")
	}
	return nil
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
	if err != nil {
		return info, errors.Wrap(err, "get CDN node status error")
	}
	return info, nil
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
