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
	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/cache"
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
	Do(*FileManager)
}

type FileManager struct {
	taskChan   chan FileTask
	Keypair    signature.KeyringPair
	Address    string
	PrivateKey *ecdsa.PrivateKey
	Message    string
	Account    string
	Sign       string
	*cache.Cache
	SelflessMode bool
	*CryptoManager
}

type CryptoManager struct {
	Key  *ecies.PrivateKey
	Date time.Time
}

func (a *FileManager) GetAESKey(pubkey []byte) ([]byte, []byte, error) {
	return GetAESKeyEncryptedWithECDH(a, pubkey)
}

func NewFileManager(sk string, c *cache.Cache, csize int, selfless bool) (*FileManager, error) {
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

	acc := utils.EncodePubkey(keypair.PublicKey, config.GetConfig().Network)

	sign, err := utils.SignedSR25519WithMnemonic(keypair.URI, msg)
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	priKey, err := crypto.HexToECDSA(sk)
	if err != nil {
		return nil, errors.Wrap(err, "new file manager error")
	}
	return &FileManager{
		taskChan:      make(chan FileTask, csize),
		Keypair:       keypair,
		Address:       crypto.PubkeyToAddress(priKey.PublicKey).Hex(),
		Account:       acc,
		Message:       msg,
		PrivateKey:    priKey,
		SelflessMode:  selfless,
		Cache:         c,
		Sign:          hex.EncodeToString(sign),
		CryptoManager: &CryptoManager{},
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
			pool.Submit(func() { task.Do(m) })
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

func (t *FileProvideTask) Do(fmg *FileManager) {
	if t.TaskType == TYPE_PROVIDE {
		t.PushFile(fmg)
	} else if t.TaskType == TYPE_RETRIEVE {
		t.FetchFile(fmg)
	}
}

func (t *FileProvideTask) FetchFile(fmg *FileManager) {
	if item := fmg.Get(t.Did); item.Value != "" {
		t.Path = item.Value
		t.Callback(client.NewResponse(200, "success", t))
		return
	}
	u, err := url.JoinPath(t.MinerAddr, "fragment")
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}
	if err = client.GetFileFromStorageNode(u,
		fmg.Account, fmg.Message, fmg.Sign,
		t.Fid, t.Did, t.Path,
	); err != nil {
		t.Callback(client.NewResponse(500, err.Error(), t))
		return
	}
	t.Callback(client.NewResponse(200, "success", t))
}

func (t *FileProvideTask) PushFile(fmg *FileManager) {

	var (
		aeskey, pubkey []byte
		epath          string = t.Path
	)

	fs, err := os.Stat(t.Path)
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}

	if !fmg.SelflessMode {
		aeskey, pubkey, err = fmg.GetAESKey(t.TeePubkey)
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
		Provider:  fmg.Address,
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

func (t *FileStorageTask) Do(fmg *FileManager) {
	if t.TaskType == TYPE_RETRIEVE {
		t.FetchFile(fmg)
	} else if t.TaskType == TYPE_PROVIDE {
		t.PushFile(fmg)
	}
}

func (t *FileStorageTask) FetchFile(fmg *FileManager) {
	if t.Did == "" {
		req := client.FileRequest{
			Pubkey:    crypto.CompressPubkey(&fmg.PrivateKey.PublicKey),
			Fid:       t.Fid,
			Timestamp: time.Now().Format(TIME_LAYOUT),
		}
		jbytes, _ := json.Marshal(&req)
		sign, _ := utils.SignWithSecp256k1PrivateKey(fmg.PrivateKey, jbytes)
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
	// get data from cache
	if item := fmg.Get(t.Did); item.Value != "" {
		t.Path = item.Value
		t.Callback(client.NewResponse(200, "success", t))
		return
	} else if t.Token == "" {
		t.Callback(client.NewResponse(400, "retrieving local data but not hitting cache", t))
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

func (t *FileStorageTask) PushFile(fmg *FileManager) {
	u, err := url.JoinPath(t.MinerAddr, "fragment")
	if err != nil {
		t.Callback(client.NewResponse(400, err.Error(), t))
		return
	}
	if err := client.PushFileToStorageNode(u,
		fmg.Account, fmg.Message, fmg.Sign,
		t.Fid, t.Did, t.Path); err != nil {
		t.Callback(client.NewResponse(500, err.Error(), t))
		return
	}
	t.Callback(client.NewResponse(200, "success", t))
}

func GetAESKeyEncryptedWithECDH(fmg *FileManager, pubkey []byte) ([]byte, []byte, error) {
	var err error

	if fmg.Key == nil || time.Since(fmg.Date) > time.Hour*24*7 {
		fmg.Key, err = ecies.GenerateKey()
		if err != nil {
			return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
		}
		fmg.Date = time.Now()
	}
	pk, err := ecies.NewPublicKeyFromBytes(pubkey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}

	key, err := fmg.Key.ECDH(pk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get aes key with ECDH error")
	}
	return key, fmg.Key.PublicKey.Bytes(true), nil
}

func GetAESKeyEncryptedWithRsa(fmg *FileManager, pubkey []byte) ([]byte, []byte, error) {
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
