package sdkgo_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/retriever"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/pkg/errors"
)

var (
	ErrorNotFound = errors.New("not found")
)

func TestErrorWarp(t *testing.T) {
	err := errors.Wrap(ErrorNotFound, "test error warp")
	t.Log(errors.Unwrap(errors.Unwrap(err)))
}

func TestUplaodWithPre(t *testing.T) {
	baseUrl := "https://retriever.cess.network"
	territory := "test1"
	filename := "test_random_file"
	mnemonic := "wing horse perfect monkey build squirrel embrace jacket frost make know save"
	keyPair, err := signature.KeyringPairFromSecret(mnemonic, 0)
	if err != nil {
		t.Fatal(err)
	}
	message := fmt.Sprint(time.Now().Unix())
	sign, err := retriever.SignedSR25519WithMnemonic(mnemonic, []byte(message))
	if err != nil {
		t.Fatal(err)
	}
	acc := chain.EncodePubkey(keyPair.PublicKey, 11330)
	token, err := retriever.GenGatewayAccessToken(baseUrl, message, acc, sign)
	if err != nil {
		t.Fatal(err)
	}
	st := time.Now()
	buf := make([]byte, 1024*1024*129)
	if _, err = rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create("./source_file")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(buf); err != nil {
		t.Fatal(err)
	}
	t.Log("gen random time", time.Since(st))
	st = time.Now()
	fid, err := retriever.UploadFile(baseUrl, token, territory, filename, bytes.NewBuffer(buf), true)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("fid:", fid, "spend time:", time.Since(st))
}

func TestGetCapsuleAndDownloadData(t *testing.T) {
	baseUrl := "https://retriever.cess.network"
	fid := "704db5a38548c13ef23ff465622e474354acd2ccfd32f0313cb33e3cf3f8a652" //704db5a38548c13ef23ff465622e474354acd2ccfd32f0313cb33e3cf3f8a652
	mnemonic := "wing horse perfect monkey build squirrel embrace jacket frost make know save"

	capsule, pubkey, err := retriever.GetPreCapsuleAndGatewayPubkey(baseUrl, fid)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("capsule:", string(capsule))
	t.Log("gateway pubkey:", pubkey)
	rk, pkX, err := retriever.GenReEncryptionKey(mnemonic, pubkey)
	if err != nil {
		t.Fatal(err)
	}
	err = retriever.DownloadData(baseUrl, fid, "", "./rand_file", capsule, rk, pkX)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("success")
}
