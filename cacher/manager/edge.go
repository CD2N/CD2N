package manager

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"time"

	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/cache"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
)

type OffloadingTaskExecutor struct {
	pool         *ants.Pool
	nodeAcc      string
	tempDir      string
	privateKey   *ecdsa.PrivateKey
	selflessMode bool
	dataCache    *cache.Cache
}

func (te *OffloadingTaskExecutor) ClaimDataFromRetriever(task Task) error {
	req := tsproto.FileRequest{
		Pubkey:    crypto.CompressPubkey(&te.privateKey.PublicKey),
		Timestamp: time.Now().Format(TIME_LAYOUT),
	}
	jbytes, _ := json.Marshal(&req)
	sign, _ := utils.SignWithSecp256k1PrivateKey(te.privateKey, jbytes)
	req.Sign = hex.EncodeToString(sign)
	u, err := url.JoinPath(task.Addr, tsproto.CLAIM_DATA_URL)
	if err != nil {
		return errors.Wrap(err, "cliam data from retriever error")
	}
	_, err = tsproto.ClaimFile(u, req)
	if err != nil {
		return errors.Wrap(err, "cliam data from retriever error")
	}
	return nil
}

func (te *OffloadingTaskExecutor) Execute(task Task) error {
	return te.pool.Submit(func() {

	})
}
