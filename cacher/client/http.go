package client

import (
	"bytes"
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

const (
	FRAGMENT_SIZE   = 8 * 1024 * 1024
	NODE_STATUS_URL = "/status"
	CLAIM_DATA_URL  = "/claim"
	PUSH_DATA_URL   = "/provide"
	FETCH_DATA_URL  = "/fetch"
)

type Cd2nNode struct {
	WorkAddr  string `json:"work_addr"`
	TeeAddr   string `json:"tee_addr"`
	TeePubkey []byte `json:"tee_pubkey"`
	EndPoint  string `json:"endpoint"`
	RedisAddr string `json:"redis_addr"`
	PoolId    string `json:"poolid"`
	IsGateway bool   `json:"is_gateway"`
}

type FileRequest struct {
	Pubkey    []byte `json:"pubkey"`
	Fid       string `json:"fid"`
	Timestamp string `json:"timestamp"`
	Sign      string `json:"sign"`
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
