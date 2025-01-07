package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"time"

	"github.com/CD2N/CD2N/cacher/client"
	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CESSProject/cess-go-tools/cacher"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	ecies "github.com/ecies/go/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

const (
	TYPE_PROVIDE  = "provide"
	TYPE_RETRIEVE = "retrieve"
)

type Endpoint struct {
	MinerAcc  string `json:"miner_acc"`
	MinerAddr string `json:"miner_addr"`
}

type FileTask interface {
	Do(*Resource)
}

type FileManager struct {
	taskChan chan FileTask
	Keypair  signature.KeyringPair
	Resource
}

type Resource struct {
	Address    string
	PrivateKey *ecdsa.PrivateKey
	Message    string
	Account    string
	Sign       string
	cacher.FileCache
	SelflessMode bool
	*CryptoManager
}

type CryptoManager struct {
	Key  *ecies.PrivateKey
	Date time.Time
}

func (a *Resource) GetAESKey(pubkey []byte) ([]byte, []byte, error) {
	return GetAESKeyEncryptedWithECDH(a, pubkey)
}

func NewFileManager(sk string, cache cacher.FileCache, csize int, selfless bool) (*FileManager, error) {
	if csize <= 0 {
		csize = DEFAULT_TASK_CHANNEL_SIZE
	}
	msg := utils.GetRandomcode(16)
	mnemonic, err := utils.GenerateMnemonic()
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	keypair, err := signature.KeyringPairFromSecret(mnemonic, 0)
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	acc, err := utils.EncodePublicKeyAsCessAccount(keypair.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	sign, err := utils.SignedSR25519WithMnemonic(keypair.URI, msg)
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	priKey, err := crypto.HexToECDSA(sk)
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	return &FileManager{
		taskChan: make(chan FileTask, csize),
		Keypair:  keypair,
		Resource: Resource{
			Address:       crypto.PubkeyToAddress(priKey.PublicKey).Hex(),
			Account:       acc,
			Message:       msg,
			PrivateKey:    priKey,
			SelflessMode:  selfless,
			FileCache:     cache,
			Sign:          hex.EncodeToString(sign),
			CryptoManager: &CryptoManager{},
		},
	}, nil
}

func (m *FileManager) GetTaskChannel() chan<- FileTask {
	return m.taskChan
}

func (m *FileManager) RunTaskServer(ctx context.Context) error {
	pool, err := ants.NewPool(2048)
	if err != nil {
		return errors.Wrap(err, "run task server")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case task := <-m.taskChan:
			pool.Submit(func() { task.Do(&m.Resource) })
		}
	}
}

type FileProvideTask struct {
	Task
	Callback
	TaskType string `json:"-"`
	Endpoint
	TeePubkey []byte `json:"tee_pubkey"`
	Fid       string `json:"fid"`
	Path      string `json:"path"`
}

func (t FileProvideTask) String() string {
	data := map[string]any{
		"tid":      t.Tid,
		"did":      t.Did,
		"fid":      t.Fid,
		"tee":      t.TeePubkey,
		"type":     t.TaskType,
		"path":     t.Path,
		"endpoint": t.Endpoint,
	}
	jbytes, _ := json.Marshal(data)
	return string(jbytes)
}

func (t *FileProvideTask) Do(res *Resource) {
	if t.TaskType == TYPE_PROVIDE {
		t.PushFile(res)
	} else if t.TaskType == TYPE_RETRIEVE {
		t.FetchFile(res)
	}
}

func (t *FileProvideTask) FetchFile(res *Resource) {
	if fpath, err := res.GetCacheRecord(t.Did); err == nil && fpath != "" {
		t.Path = fpath
		t.Callback(client.NewResponse(200, "success", t))
		return
	}
	u, err := url.JoinPath(t.MinerAddr, "fragment")
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}
	if err = client.GetFileFromStorageNode(u,
		res.Account, res.Message, res.Sign,
		t.Fid, t.Did, t.Path,
	); err != nil {
		t.Callback(client.NewResponse(500, err.Error(), t))
		return
	}
	t.Callback(client.NewResponse(200, "success", t))
}

func (t *FileProvideTask) PushFile(res *Resource) {

	var (
		aeskey, pubkey []byte
		epath          string = t.Path
	)

	fs, err := os.Stat(t.Path)
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}

	if !res.SelflessMode {
		aeskey, pubkey, err = res.GetAESKey(t.TeePubkey)
		if err != nil {
			t.Callback(client.NewResponse(400, err.Error(), t))
			return
		}
		//encrypt file
		tidBytes, _ := hex.DecodeString(t.Tid)
		epath, err = utils.EncryptFile(t.Path, aeskey, tidBytes)
		if err != nil {
			t.Callback(client.NewResponse(400, err.Error(), t))
			return
		}

		defer os.Remove(epath)
	}

	fmeta := client.FileMeta{
		Tid:       t.Tid,
		Did:       t.Did,
		Size:      fs.Size(),
		Key:       hex.EncodeToString(pubkey),
		Provider:  res.Address,
		Timestamp: time.Now().Format(TIME_LAYOUT),
	}
	jbytes, err := json.Marshal(fmeta)
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}
	u, err := url.JoinPath(t.Addr, client.PUSH_DATA_URL)
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}

	if _, err = client.PushFile(u, epath,
		map[string][]byte{"metadata": jbytes}); err != nil {
		t.Callback(client.NewResponse(500, err.Error(), t))
		return
	}
	t.Callback(client.NewResponse(200, "success", t))
}

type FileStorageTask struct {
	Task
	Callback
	TaskType string `json:"-"`
	Endpoint
	Fid       string   `json:"fid"`
	Count     int      `json:"count"`
	Fragments []string `json:"fragments"`
	Token     string   `json:"token"`
	Sign      string   `json:"sign"`
	Path      string   `json:"path"`
}

func (t FileStorageTask) String() string {
	data := map[string]any{
		"tid":       t.Tid,
		"did":       t.Did,
		"fid":       t.Fid,
		"fragments": t.Fragments,
		"token":     t.Token,
		"count":     t.Count,
		"path":      t.Path,
		"endpoint":  t.Endpoint,
	}
	jbytes, _ := json.Marshal(data)
	return string(jbytes)
}

func (t *FileStorageTask) Do(res *Resource) {
	if t.TaskType == TYPE_RETRIEVE {
		t.FetchFile(res)
	} else if t.TaskType == TYPE_PROVIDE {
		t.PushFile(res)
	}
}

func (t *FileStorageTask) FetchFile(res *Resource) {
	if t.Did == "" {
		req := client.FileRequest{
			Pubkey:    crypto.CompressPubkey(&res.PrivateKey.PublicKey),
			Fid:       t.Fid,
			Timestamp: time.Now().Format(TIME_LAYOUT),
		}
		jbytes, _ := json.Marshal(&req)
		sign, _ := utils.SignWithSecp256k1PrivateKey(res.PrivateKey, jbytes)
		req.Sign = hex.EncodeToString(sign)
		u, err := url.JoinPath(t.Addr, client.CLAIM_DATA_URL)
		if err != nil {
			t.Callback(client.NewResponse(400, err.Error(), t))
		}
		resp, err := client.ClaimFile(u, req)
		if err != nil {
			t.Callback(client.NewResponse(500, err.Error(), t))
			return
		}
		t.Token = resp.Token
		t.Fragments = resp.Fragments
		t.Count = len(resp.Fragments)
		t.Callback(client.NewResponse(200, "success", t))
		return
	}
	u, err := url.JoinPath(t.Addr, client.FETCH_DATA_URL)
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
	}
	data, err := client.FetchFile(u, t.Token, t.Fid, t.Did)
	if err != nil {
		t.Callback(client.NewResponse(500, err.Error(), t))
		return
	}
	f, err := os.Create(t.Path)
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}
	defer f.Close()
	_, err = f.Write(data)
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}
	t.Callback(client.NewResponse(200, "success", t))
}

func (t *FileStorageTask) PushFile(res *Resource) {
	u, err := url.JoinPath(t.MinerAddr, "fragment")
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}
	if err := client.PushFileToStorageNode(u,
		res.Account, res.Message, res.Sign,
		t.Fid, t.Did, t.Path); err != nil {
		t.Callback(client.NewResponse(500, err.Error(), t))
		return
	}
	t.Callback(client.NewResponse(200, "success", t))
}

func GetAESKeyEncryptedWithECDH(a *Resource, pubkey []byte) ([]byte, []byte, error) {
	var err error

	if a.Key == nil || time.Since(a.Date) > time.Hour*24*7 {
		a.Key, err = ecies.GenerateKey()
		if err != nil {
			return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
		}
		a.Date = time.Now()
	}
	pk, err := ecies.NewPublicKeyFromBytes(pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}

	key, err := a.Key.ECDH(pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}
	return key, a.Key.PublicKey.Bytes(true), nil
}

func GetAESKeyEncryptedWithRsa(a *Resource, pubkey []byte) ([]byte, []byte, error) {
	var err error
	rsaPk, err := x509.ParsePKCS1PublicKey(pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with RSA error")
	}
	code := utils.GetRandomcode(32)
	hash := sha256.New()
	hash.Write([]byte(code))
	aeskey := hash.Sum(nil)
	eAesKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPk, aeskey, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with RSA error")
	}
	return aeskey, eAesKey, nil
}
