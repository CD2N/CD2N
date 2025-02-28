package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/AstaFrode/go-substrate-rpc-client/v4/registry/retriever"
	"github.com/AstaFrode/go-substrate-rpc-client/v4/registry/state"
	"github.com/AstaFrode/go-substrate-rpc-client/v4/types"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	cess "github.com/CESSProject/cess-go-sdk"
	cchain "github.com/CESSProject/cess-go-sdk/chain"
	"github.com/pkg/errors"
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

func TestParseEvent(t *testing.T) {
	txhash := "0xa639ed9e2117de3971434a9f654a58c475a29cb203a67f9003899aaca7161f3c"
	cli, err := NewCessChainClient(context.Background(), "", []string{"wss://testnet-rpc.cess.cloud"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := retriever.NewDefaultEventRetriever(
		state.NewEventProvider(cli.GetSubstrateAPI().RPC.State),
		cli.GetSubstrateAPI().RPC.State,
	)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := types.NewHashFromHexString(txhash)
	if err != nil {
		t.Fatal(err)
	}
	events, err := r.GetEvents(hash)
	if err != nil {
		t.Fatal(err)
	}
	//e := types.EventBalancesTransfer{}
	//e := types.EventBalancesDeposit{}
	//e := TransferEvent{}

	//e := types.EventSystemExtrinsicFailed{}
	// a := types.EventRecordsRaw([]byte{})
	// a.DecodeEventRecords()
	// a.DecodeEventRecords()
	now := time.Now()
	count := 0
	for _, event := range events {
		if event.Name == "System.ExtrinsicSuccess" {
			e := types.EventSystemExtrinsicSuccess{}

			err = chain.DecodeEvent(event, &e)
			if err != nil {
				t.Fatal(err)
			}
			count++
			t.Log(e)
		}
	}
	t.Log("time:", time.Since(now)/time.Duration(count))
}

func NewCessChainClient(ctx context.Context, mnemonic string, rpcs []string) (cchain.Chainer, error) {
	var (
		chainCli cchain.Chainer
		err      error
	)
	time.Sleep(time.Second * 15)
	for i := 0; i < 3; i++ {
		chainCli, err = cess.New(
			ctx,
			cess.ConnectRpcAddrs(rpcs),
			cess.TransactionTimeout(30*time.Second),
			cess.Mnemonic(mnemonic),
		)
		if err == nil {
			break
		}
	}
	if err != nil || chainCli == nil {
		return nil, errors.Wrap(err, "new cess chain client error")
	}
	if err = chainCli.InitExtrinsicsNameForOSS(); err != nil {
		return nil, errors.Wrap(err, "new cess chain client error")
	}
	return chainCli, nil
}

func TestParseName(t *testing.T) {
	t.Log(chain.ConvertName("index.abcd.words_map.Aabbcc_ddeecc"))
}
