package upload

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/CD2N/CD2N/sdk/sdkgo/retriever"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
)

type User struct {
	Mnemonics string `json:"mnemonics"`
	Territory string `json:"territory"`
	Capacity  uint64 `json:"capacity"`
}

type UploadController struct {
	Gateway         string        `json:"gateway"`
	Users           []User        `json:"users"`
	tokenCh         chan struct{} `json:"-"`
	rw              *sync.RWMutex `json:"-"`
	MinFileSize     int64         `json:"min_file_size"`
	MaxFileSize     int64         `json:"max_file_size"`
	DailyTarget     int64         `json:"daily_target"`
	TargetDays      int64         `json:"target_days"`
	UploadSize      uint64        `json:"upload_size"`
	DailyUploadSize uint64        `json:"daily_upload_size"`
	RunningDays     int64         `json:"running_days"`
}

func UploadFileExamples(baseUrl, territory, fpath, mnemonic string) error {
	timestamp := time.Now().Unix()
	message := fmt.Sprint(timestamp)
	hash := sha256.Sum256([]byte(message))
	sign, err := retriever.SignedSR25519WithMnemonic(mnemonic, hash[:])
	if err != nil {
		return err
	}
	keypair, err := signature.KeyringPairFromSecret(mnemonic, 11330)
	if err != nil {
		return err
	}
	token, err := retriever.GenGatewayAccessToken(baseUrl, message, keypair.Address, sign)
	if err != nil {
		return err

	}
	f, err := os.Open(fpath)
	if err != nil {
		return err

	}
	defer f.Close()
	fid, err := retriever.UploadFile(baseUrl, token, territory, f.Name(), f)
	if err != nil {
		return err

	}
	log.Println("fid:", fid)
	return nil
}

func NewUploadController() *UploadController {
	return &UploadController{
		tokenCh: make(chan struct{}, 1440),
		rw:      &sync.RWMutex{},
	}
}

func (c *UploadController) LoadJsonConfig(fpath string) error {
	data, err := os.ReadFile(fpath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, c)
}

func (c *UploadController) SaveJsonConfig(fpath string) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(fpath, data, 0755)
}

func (c *UploadController) UploadFile(ctx context.Context) {
	tempfile := "./randfile.test"
	for {
		c.rw.RLock()
		if c.RunningDays >= c.TargetDays {
			c.rw.RUnlock()
			return
		}
		c.rw.RUnlock()
		select {
		case <-ctx.Done():
			return
		case <-c.tokenCh:
			size := int64(rand.Intn(int(c.MaxFileSize-c.MinFileSize))) + c.MinFileSize
			if err := GenRandFile(tempfile, size); err != nil {
				log.Println(err)
				continue
			}
			ridx := rand.Intn(len(c.Users))
			if err := UploadFileExamples(c.Gateway, c.Users[ridx].Territory, tempfile, c.Users[ridx].Mnemonics); err != nil {
				log.Println(err)
				continue
			}
			log.Printf("file size:%d MB", size/1024/1024)
			c.rw.Lock()
			c.DailyUploadSize += uint64(size)
			c.UploadSize += uint64(size)
			c.rw.Unlock()
		}
	}
}

func (c *UploadController) Controller(ctx context.Context) {
	upTicker := time.NewTicker(time.Second * 6)
	dayTicker := time.NewTicker(time.Hour * 24)
	for {
		select {
		case <-ctx.Done():
			log.Println("task done.")
			return
		case <-upTicker.C:
			c.rw.Lock()
			if c.DailyUploadSize < uint64(c.DailyTarget) {
				c.tokenCh <- struct{}{}
			}
			c.rw.Unlock()
		case <-dayTicker.C:
			c.rw.Lock()
			c.DailyUploadSize = 0
			c.RunningDays++
			c.rw.Unlock()
		}
	}
}
