package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	r "github.com/CD2N/CD2N/sdk/sdkgo/retriever"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

type Test struct {
	Data map[int]string
}

type TransferEvent struct {
	From   []types.U8
	To     []types.U8
	Amount types.U128
}

func TestReflect(t *testing.T) {
	defer func() {
		d := recover()
		t.Log("panic type", reflect.TypeOf(d), d)
	}()
	rv := reflect.New(reflect.TypeOf(Test{})).Elem()
	rf := rv.Field(0)
	tmp := reflect.MakeMap(reflect.TypeOf(map[string]string{}))
	tmp.SetMapIndex(reflect.ValueOf(1), reflect.ValueOf("aaaa"))
	rf.Set(tmp)
	t.Log(rv)
}

// func TestParseEvent(t *testing.T) {
// 	txhash := "0xa639ed9e2117de3971434a9f654a58c475a29cb203a67f9003899aaca7161f3c"
// 	cli, err := NewCessChainClient(context.Background(), "", []string{"wss://testnet-rpc.cess.cloud"})
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	r, err := retriever.NewDefaultEventRetriever(
// 		state.NewEventProvider(cli.GetSubstrateAPI().RPC.State),
// 		cli.GetSubstrateAPI().RPC.State,
// 	)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	hash, err := types.NewHashFromHexString(txhash)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	events, err := r.GetEvents(hash)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	//e := types.EventBalancesTransfer{}
// 	//e := types.EventBalancesDeposit{}
// 	//e := TransferEvent{}

// 	//e := types.EventSystemExtrinsicFailed{}
// 	// a := types.EventRecordsRaw([]byte{})
// 	// a.DecodeEventRecords()
// 	// a.DecodeEventRecords()
// 	now := time.Now()
// 	count := 0
// 	for _, event := range events {
// 		if event.Name == "TransactionPayment.TransactionFeePaid" {
// 			e := types.EventTransactionPaymentTransactionFeePaid{}

// 			// err = chain.DecodeEvent(event, &e)
// 			// if err != nil {
// 			// 	t.Fatal(err)
// 			// }
// 			// count++
// 			t.Log(e)
// 		}
// 	}
// 	t.Log("time:", time.Since(now)/time.Duration(count))
// }

// func NewCessChainClient(ctx context.Context, mnemonic string, rpcs []string) (cchain.Chainer, error) {
// 	var (
// 		chainCli cchain.Chainer
// 		err      error
// 	)
// 	time.Sleep(time.Second * 15)
// 	for i := 0; i < 3; i++ {
// 		chainCli, err = cess.New(
// 			ctx,
// 			cess.ConnectRpcAddrs(rpcs),
// 			cess.TransactionTimeout(30*time.Second),
// 			cess.Mnemonic(mnemonic),
// 		)
// 		if err == nil {
// 			break
// 		}
// 	}
// 	if err != nil || chainCli == nil {
// 		return nil, errors.Wrap(err, "new cess chain client error")
// 	}
// 	if err = chainCli.InitExtrinsicsNameForOSS(); err != nil {
// 		return nil, errors.Wrap(err, "new cess chain client error")
// 	}
// 	return chainCli, nil
// }

func TestParseName(t *testing.T) {
	t.Log(chain.ConvertName("index.abcd.words_map.Aabbcc_ddeecc"))
}

func TestUploadParts(t *testing.T) {
	timestamp := time.Now().Unix()
	message := fmt.Sprint(timestamp)
	hash := sha256.Sum256([]byte(message))
	mnemonic := "father weird payment camp saddle assault dune knee network prize enemy liquid"
	baseUrl := "http://154.194.34.206:1306"
	sign, err := r.SignedSR25519WithMnemonic(mnemonic, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	keypair, err := signature.KeyringPairFromSecret(mnemonic, 11330)
	if err != nil {
		t.Fatal(err)
	}
	token, err := r.GenGatewayAccessToken(baseUrl, message, keypair.Address, sign)
	if err != nil {
		t.Fatal(err)

	}
	t.Log(token)
	info, err := r.RequestToUploadParts(baseUrl, "./kugou_release_20022.exe", token, "test1", "kugo.exe", "", 16*1024*1024)
	if err != nil {
		//t.Fatal(err)

	}
	t.Log(info)
	info.PartsCount = 3
	res, err := r.UploadFileParts(baseUrl, token, "./kugou_release_20022.exe", &info)
	if err != nil {
		t.Fatal(err)

	}
	t.Log(res)
}
