package retriever

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/vedhavyas/go-subkey/sr25519"
)

const (
	GATEWAY_GENTOKEN_URL      = "/gateway/gentoken"
	GATEWAY_UPLOADFILE_URL    = "/gateway/upload/file"
	GATEWAY_PARTUPLOAD_URL    = "/gateway/part-upload"
	GATEWAY_UPLOADPART_URL    = "/gateway/upload/part"
	GATEWAY_GETFILE_URL       = "/gateway/download"
	RETRIEVER_QUERYDATA_URL   = "/querydata"
	RETRIEVER_FETCHDATA_URL   = "/cache-fetch"
	RETRIEVER_NODESTATUS_URL  = "/status"
	RETRIEVER_GETCAPACITY_URL = "/capacity"

	DEFAULT_PART_SIZE = 32 * 1024 * 1024
)

type Response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data any    `json:"data"`
}

type FileInfo struct {
	Fid       string     `json:"fid"`
	FileName  string     `json:"file_name"`
	BaseDir   string     `json:"base_dir"`
	FileSize  int64      `json:"file_size"`
	Owner     []byte     `json:"owner"`
	Territory string     `json:"territory"`
	Segments  []string   `json:"segments"`
	Fragments [][]string `json:"fragments"`
}

type PartsInfo struct {
	ShadowHash string    `json:"shadow_hash,omitempty"`
	FileName   string    `json:"file_name,omitempty"`
	DirName    string    `json:"dir_name,omitempty"`
	Archive    string    `json:"archive,omitempty"`
	Territory  string    `json:"territory,omitempty"`
	Parts      []string  `json:"parts,omitempty"`
	PartsCount int       `json:"parts_count,omitempty"`
	TotalParts int       `json:"total_parts,omitempty"`
	PartSize   int64     `json:"-"`
	TotalSize  int64     `json:"total_size,omitempty"`
	UpdateDate time.Time `json:"update_date,omitempty"`
}

func SignedSR25519WithMnemonic(mnemonic string, msg []byte) ([]byte, error) {

	pri, err := sr25519.Scheme{}.FromPhrase(mnemonic, "")
	if err != nil {
		return nil, errors.New("invalid mnemonic")
	}
	return pri.Sign(msg)
}

func GenGatewayAccessToken(baseUrl, message, account string, sign []byte) (string, error) {
	var (
		token  string
		err    error
		buffer *bytes.Buffer
	)
	data := url.Values{
		"account": {account},
		"message": {message},
		"sign":    {hex.EncodeToString(sign)},
	}
	dataString := data.Encode()
	buffer = bytes.NewBufferString(dataString)
	u, err := url.JoinPath(baseUrl, GATEWAY_GENTOKEN_URL)
	if err != nil {
		return token, errors.Wrap(err, "gen gateway access token error")
	}
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	body, err := SendHttpRequest(http.MethodPost, u, headers, buffer)
	if err != nil {
		return token, errors.Wrap(err, "gen gateway access token error")
	}
	resp := Response{
		Data: &token,
	}
	err = json.Unmarshal(body, &resp)
	if err != nil {
		return token, errors.Wrap(err, "gen gateway access token error")
	}
	return token, nil
}

func uploadFile(baseUrl, token, territory, filename string, file io.Reader, async, noProxy bool) ([]byte, error) {
	var (
		err    error
		buffer bytes.Buffer
	)
	writer := multipart.NewWriter(&buffer)
	writer.WriteField("territory", territory)
	if async {
		writer.WriteField("async", "true")
	}
	if noProxy {
		writer.WriteField("noProxy", "true")
	}

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, errors.Wrap(err, "upload user file error")
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, errors.Wrap(err, "upload user file error")
	}

	if err := writer.Close(); err != nil {
		return nil, errors.Wrap(err, "upload user file error")
	}
	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
		"token":        fmt.Sprintf("Bearer %s", token),
	}
	u, err := url.JoinPath(baseUrl, GATEWAY_UPLOADFILE_URL)
	if err != nil {
		return nil, errors.Wrap(err, "upload user file error")
	}
	body, err := SendHttpRequest(http.MethodPost, u, headers, &buffer)
	if err != nil {
		return nil, errors.Wrap(err, "upload user file error")
	}
	return body, nil
}

func UploadFile(baseUrl, token, territory, filename string, file io.Reader) (string, error) {
	var (
		fid string
	)
	body, err := uploadFile(baseUrl, token, territory, filename, file, false, false)
	if err != nil {
		return "", errors.Wrap(err, "synchronous upload failed")
	}
	resp := Response{
		Data: &fid,
	}
	if err = json.Unmarshal(body, &resp); err != nil {
		return fid, errors.Wrap(err, "synchronous upload failed")
	}
	return fid, nil
}

func AsyncUploadFile(baseUrl, token, territory, filename string, file io.Reader, noProxy bool) (FileInfo, error) {
	var (
		info FileInfo
	)
	body, err := uploadFile(baseUrl, token, territory, filename, file, false, noProxy)
	if err != nil {
		return info, errors.Wrap(err, "asynchronous upload failed")
	}
	resp := Response{
		Data: &info,
	}
	if err = json.Unmarshal(body, &resp); err != nil {
		return info, errors.Wrap(err, "asynchronous upload failed")
	}
	return info, nil
}

func uploadFileParts(baseUrl, token, fpath string, info *PartsInfo, async, noProxy bool) ([]byte, error) {
	var (
		err    error
		buffer bytes.Buffer
	)
	writer := multipart.NewWriter(&buffer)
	writer.WriteField("shadowhash", info.ShadowHash)
	writer.WriteField("partid", fmt.Sprint(info.PartsCount))
	if async {
		writer.WriteField("async", "true")
	}
	if noProxy {
		writer.WriteField("noProxy", "true")
	}
	part, err := writer.CreateFormFile("file", info.Parts[info.PartsCount])
	if err != nil {
		return nil, errors.Wrap(err, "upload file part error")
	}

	if info.DirName != "" {
		file, err := os.Open(filepath.Join(fpath, info.Parts[info.PartsCount]))
		if err != nil {
			return nil, errors.Wrap(err, "upload file part error")
		}
		defer file.Close()
		_, err = io.Copy(part, file)
		if err != nil {
			return nil, errors.Wrap(err, "upload file part error")
		}

	} else {
		file, err := os.Open(fpath)
		if err != nil {
			return nil, errors.Wrap(err, "upload file part error")
		}
		defer file.Close()
		size := info.PartSize
		_, err = file.Seek(int64(info.PartsCount)*size, io.SeekStart)
		if err != nil {
			return nil, errors.Wrap(err, "upload file part error")
		}
		if int64(info.PartsCount+1)*size > info.TotalSize {
			size = info.TotalSize % size
		}
		_, err = io.CopyN(part, file, size)
		if err != nil {
			return nil, errors.Wrap(err, "upload file part error")
		}
		if err := writer.Close(); err != nil {
			return nil, errors.Wrap(err, "upload file part error")
		}
	}

	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
		"token":        fmt.Sprintf("Bearer %s", token),
	}
	u, err := url.JoinPath(baseUrl, GATEWAY_UPLOADPART_URL)
	if err != nil {
		return nil, errors.Wrap(err, "upload file part error")
	}
	body, err := SendHttpRequest(http.MethodPost, u, headers, &buffer)
	if err != nil {
		return nil, errors.Wrap(err, "upload file part error")
	}
	info.PartsCount++
	return body, nil
}

func UploadFileParts(baseUrl, token, fpath string, info *PartsInfo) (string, error) {
	var (
		fid string
	)
	body, err := uploadFileParts(baseUrl, token, fpath, info, false, false)
	if err != nil {
		return fid, errors.Wrap(err, "synchronous upload failed")
	}
	resp := Response{}
	if err = json.Unmarshal(body, &resp); err != nil {
		return fid, errors.Wrap(err, "synchronous upload failed")
	}
	fid = fmt.Sprint(resp.Data)
	return fid, nil
}

func AsyncUploadFileParts(baseUrl, token, fpath string, info *PartsInfo, noProxy bool) (FileInfo, error) {
	var (
		finfo FileInfo
		resp  Response
		pid   string
	)
	body, err := uploadFileParts(baseUrl, token, fpath, info, false, false)
	if err != nil {
		return finfo, errors.Wrap(err, "asynchronous upload failed")
	}
	if info.PartsCount == info.TotalParts {
		resp.Data = &finfo
	} else {
		resp.Data = &pid
	}
	if err = json.Unmarshal(body, &resp); err != nil {
		return finfo, errors.Wrap(err, "asynchronous upload failed")
	}
	if pid != "" && finfo.Fid == "" {
		finfo.Fid = pid
	}
	return finfo, nil
}

func RequestToUploadParts(baseUrl, fpath, token, territory, filename, achive string, partSize int64) (PartsInfo, error) {
	var info PartsInfo
	fs, err := os.Stat(fpath)
	if err != nil {
		return info, errors.Wrap(err, "request to upload file parts error")
	}
	if fs.IsDir() {
		info, err = CreatePartsInfoForDir(fpath, filename, achive)
		if err != nil {
			return info, errors.Wrap(err, "request to upload file parts error")
		}
	} else {
		info, err = CreatePartsInfoForFile(fpath, filename, fs.Size(), partSize)
		if err != nil {
			return info, errors.Wrap(err, "request to upload file parts error")
		}
	}
	info.Territory = territory
	info.UpdateDate = time.Now()
	headers := map[string]string{
		"Content-Type": "application/json",
		"token":        fmt.Sprintf("Bearer %s", token),
	}
	u, err := url.JoinPath(baseUrl, GATEWAY_PARTUPLOAD_URL)
	if err != nil {
		return info, errors.Wrap(err, "request to upload file parts error")
	}
	jbytes, err := json.Marshal(info)
	if err != nil {
		return info, errors.Wrap(err, "request to upload file parts error")
	}
	_, err = SendHttpRequest(http.MethodPost, u, headers, bytes.NewBuffer(jbytes))
	return info, errors.Wrap(err, "request to upload file parts error")
}

func CreatePartsInfoForFile(fpath, filename string, fileSize, partSize int64) (PartsInfo, error) {

	if partSize <= DEFAULT_PART_SIZE {
		partSize = DEFAULT_PART_SIZE
	}
	if partSize > fileSize {
		partSize = fileSize
	}
	if filename == "" {
		filename = filepath.Base(fpath)
	}
	info := PartsInfo{
		FileName:   filename,
		TotalSize:  fileSize,
		PartSize:   partSize,
		TotalParts: int((fileSize + (partSize - fileSize%partSize)) / partSize),
	}

	f, err := os.Open(fpath)
	if err != nil {
		return info, errors.Wrap(err, "create parts info for file error")
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	info.Parts = make([]string, 0, info.TotalParts)
	hash := sha256.New()
	buf := make([]byte, partSize)
	for i := 0; i < info.TotalParts; i++ {
		n, err := reader.Read(buf)
		if err != nil {
			return info, errors.Wrap(err, "create parts info for file error")
		}
		partHash := sha256.Sum256(buf[:n])
		info.Parts = append(info.Parts, hex.EncodeToString(partHash[:]))
		if n >= 32 {
			hash.Write(buf[:32])
		} else {
			hash.Write(buf[:n])
			hash.Write(make([]byte, 32-n))
		}
	}
	info.ShadowHash = hex.EncodeToString(hash.Sum(nil))
	return info, nil
}

func CreatePartsInfoForDir(fpath, dirname, archive string) (PartsInfo, error) {
	info := PartsInfo{
		DirName: dirname,
		Archive: archive,
	}
	entries, err := os.ReadDir(fpath)
	if err != nil {
		return info, errors.Wrap(err, "create parts info for dir error")
	}
	info.Parts = make([]string, 0, len(entries))
	hash := sha256.New()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(fpath, entry.Name()))
		if err != nil {
			return info, errors.Wrap(err, "create parts info for dir error")
		}
		buf := make([]byte, 32)
		if _, err = f.Read(buf); err != nil {
			f.Close()
			return info, errors.Wrap(err, "create parts info for dir error")
		}
		stat, err := f.Stat()
		if err != nil {
			f.Close()
			return info, errors.Wrap(err, "create parts info for dir error")
		}
		hash.Write(buf)
		info.Parts = append(info.Parts, f.Name())
		info.TotalParts++
		info.TotalSize += stat.Size()
		f.Close()
	}
	info.ShadowHash = hex.EncodeToString(hash.Sum(nil))
	return info, nil
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
