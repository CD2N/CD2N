package upload

import (
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/CD2N/CD2N/sdk/sdkgo/retriever"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
)

func UploadFileExamples(baseUrl, territory, fpath, mnemonic string) {
	timestamp := time.Now().Unix()
	message := fmt.Sprint(timestamp)
	hash := sha256.Sum256([]byte(message))
	sign, err := retriever.SignedSR25519WithMnemonic(mnemonic, hash[:])
	if err != nil {
		log.Fatal(err)
	}
	keypair, err := signature.KeyringPairFromSecret(mnemonic, 11330)
	if err != nil {
		log.Fatal(err)
	}
	token, err := retriever.GenGatewayAccessToken(baseUrl, message, keypair.Address, sign)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Open(fpath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	log.Println("token:", fmt.Sprintf("Bearer %s", token))
	fid, err := retriever.UploadFile(baseUrl, token, territory, f.Name(), f)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("fid:", fid)
}
