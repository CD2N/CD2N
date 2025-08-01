package sdkgo_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/retriever"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry"
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

func TestSdkEventMap(t *testing.T) {
	cli, err := chain.NewLightCessClient(
		"wing horse perfect monkey build squirrel embrace jacket frost make know save",
		[]string{"wss://t2-rpc.cess.network"},
	)
	if err != nil {
		t.Fatal(err)
	}

	factory := registry.NewFactory()
	eventRegistry, err := factory.CreateEventRegistry(cli.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	eventMap := make(map[string][]string)
	for _, event := range eventRegistry {
		s := strings.Split(event.Name, ".")
		if events, ok := eventMap[s[0]]; ok {
			events = append(events, event.Name)
			eventMap[s[0]] = events
		} else {
			eventMap[s[0]] = []string{event.Name}
		}
	}
	for k, v := range eventMap {
		t.Log(k)
		for _, event := range v {
			t.Log("    ", event)
		}
	}
}

func TestSdkEvents(t *testing.T) {
	cli, err := chain.NewLightCessClient(
		"wing horse perfect monkey build squirrel embrace jacket frost make know save",
		[]string{"wss://t2-rpc.cess.network"},
	)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := cli.SubstrateAPI.RPC.Chain.SubscribeNewHeads()
	if err != nil {
		t.Fatal(err)
	}
	// callRegistry, err := registry.NewFactory().CreateCallRegistry(cli.Metadata)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	defer sub.Unsubscribe()
	for {
		select {
		case header := <-sub.Chan():
			hash, err := cli.SubstrateAPI.RPC.Chain.GetBlockHash(uint64(header.Number))
			if err != nil {
				t.Log(err)
				continue
			}
			data, err := cli.ParseBlockData(hash)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("parse block ", hash)
			for _, ext := range data.Extrinsics {
				jb, err := json.Marshal(ext.Events)
				if err != nil {
					t.Fatal(err)
				}
				t.Log(ext.Name, "extrinsic events", string(jb))
			}
			jb, err := json.Marshal(data.SystemEvents)
			if err != nil {
				t.Fatal(err)
			}
			t.Log("system events", string(jb))
			// block, err := cli.SubstrateAPI.RPC.Chain.GetBlock(hash)
			// if err != nil {
			// 	t.Log(err)
			// 	continue
			// }
			// t.Log(hash.Hex(), "Block Extrinsics")
			// for _, e := range block.Block.Extrinsics {
			// 	data, err := codec.Encode(e.Method)
			// 	if err != nil {
			// 		t.Log("encode error", err)
			// 	}
			// 	h := blake2b.Sum256(data)
			// 	call := callRegistry[e.Method.CallIndex]
			// 	t.Log(call.Name, e.Signature.Signer.AsAddress32, hexutil.Encode(h[:]))
			// 	for _, field := range call.Fields {
			// 		t.Log("    ", field.Name)
			// 	}
			// }
			// events, err := cli.Retriever.GetEvents(hash)
			// if err != nil {
			// 	t.Log(err)
			// 	continue
			// }
			// t.Log(hash.Hex(), "Block Events")
			// for _, e := range events {
			// 	t.Log(e.Name)
			// }
		case err := <-sub.Err():
			t.Fatal(err)
		}
	}
}
