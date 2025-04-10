package chain

import (
	"fmt"
	"math/rand"
	"time"

	rpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/retriever"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/state"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
	"github.com/pkg/errors"
)

type Client struct {
	Rpcs []string
	KeyringManager
	GenesisBlockHash types.Hash
	RuntimeVersion   *types.RuntimeVersion
	*rpc.SubstrateAPI
	Retriever retriever.EventRetriever
	Timeout   time.Duration
	Metadata  *types.Metadata
}

type Option func(*Client) error

func OptionWithRpcs(rpcs []string) Option {
	return func(c *Client) error {
		c.Rpcs = rpcs
		return nil
	}
}

func OptionWithAccounts(mnemonics []string) Option {
	return func(c *Client) error {
		keys := make([]signature.KeyringPair, 0, len(mnemonics))
		for _, m := range mnemonics {
			key, err := signature.KeyringPairFromSecret(m, 0)
			if err != nil {
				return err
			}
			keys = append(keys, key)
		}
		c.KeyringManager = NewKeyrings(keys...)
		return nil
	}
}

func OptionWithTimeout(timeout time.Duration) Option {
	return func(c *Client) error {
		if timeout <= 0 {
			timeout = time.Second * 30
		}
		c.Timeout = timeout
		return nil
	}
}

func NewLightCessClient(mnemonic string, rpcs []string) (*Client, error) {
	cli, err := NewClient(
		OptionWithRpcs(rpcs),
		OptionWithAccounts([]string{mnemonic}),
	)
	if err != nil {
		return cli, errors.Wrap(err, "new light cess client error")
	}
	return cli, nil
}

func NewClient(opts ...Option) (*Client, error) {
	client := &Client{}
	for _, opt := range opts {
		if err := opt(client); err != nil {
			return client, errors.Wrap(err, "new cess chain client error")
		}
	}
	err := client.NewSubstrateAPI()
	if err != nil {
		return client, errors.Wrap(err, "new cess chain client error")
	}
	client.Metadata, err = client.RPC.State.GetMetadataLatest()
	if err != nil {
		return client, errors.Wrap(err, "new cess chain client error")
	}
	client.GenesisBlockHash, err = client.RPC.Chain.GetBlockHash(0)
	if err != nil {
		return client, errors.Wrap(err, "new cess chain client error")
	}
	client.RuntimeVersion, err = client.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		return client, errors.Wrap(err, "new cess chain client error")
	}
	client.Retriever, err = retriever.NewDefaultEventRetriever(
		state.NewEventProvider(client.RPC.State),
		client.RPC.State,
	)
	if err != nil {
		return client, errors.Wrap(err, "new cess chain client error")
	}
	if client.Timeout <= 0 {
		client.Timeout = time.Second * 30
	}
	return client, nil
}

func (c *Client) NewSubstrateAPI() error {
	var err error
	if len(c.Rpcs) <= 0 {
		return errors.New("Invalid RPC address")
	}
	url := c.Rpcs[rand.Intn(len(c.Rpcs))]
	c.SubstrateAPI, err = rpc.NewSubstrateAPI(url)
	return err
}

func (c *Client) RefreshSubstrateApi() error {
	var err error
	for i := 0; i < 3; i++ {
		if err = c.NewSubstrateAPI(); err == nil {
			c.Metadata, err = c.RPC.State.GetMetadataLatest()
			if err != nil {
				continue
			}
			return nil
		}
	}
	return errors.Wrap(err, "refresh substrate api error")
}

func (c *Client) SubmitExtrinsic(keypair signature.KeyringPair, call types.Call, eventName string, event any, timeout time.Duration) (string, error) {

	var (
		hash string
	)
	ext := types.NewExtrinsic(call)
	key, err := types.CreateStorageKey(c.Metadata, "System", "Account", keypair.PublicKey)
	if err != nil {
		return hash, errors.Wrap(fmt.Errorf("create storage key err: %v", err), "submit extrinsic error")
	}

	var accountInfo types.AccountInfo
	ok, err := c.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		return hash, errors.Wrap(fmt.Errorf("get storage latest err: %v", err), "submit extrinsic error")
	}

	if !ok {
		return hash, errors.Wrap(errors.New("get storage latest err: empty error"), "submit extrinsic error")
	}

	o := types.SignatureOptions{
		BlockHash:          c.GenesisBlockHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        c.GenesisBlockHash,
		Nonce:              types.NewUCompactFromUInt(uint64(accountInfo.Nonce)),
		SpecVersion:        c.RuntimeVersion.SpecVersion,
		Tip:                types.NewUCompactFromUInt(0),
		TransactionVersion: c.RuntimeVersion.TransactionVersion,
	}

	err = ext.Sign(keypair, o)
	if err != nil {
		return hash, errors.Wrap(err, "submit extrinsic error")
	}

	sub, err := c.RPC.Author.SubmitAndWatchExtrinsic(ext)
	if err != nil {
		return hash, errors.Wrap(err, "submit extrinsic error")
	}
	defer sub.Unsubscribe()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case status := <-sub.Chan():
			if !status.IsInBlock {
				continue
			}
			hash = status.AsInBlock.Hex()
			if eventName == "" {
				return hash, nil
			}
			events, err := c.Retriever.GetEvents(status.AsInBlock)
			if err != nil {
				return hash, errors.Wrap(err, "submit extrinsic error")
			}
			e, err := ParseTxResult(keypair, events, eventName)
			if err != nil {
				return hash, errors.Wrap(err, "submit extrinsic error")
			}
			if e != nil && event != nil {
				if err = DecodeEvent(e, event); err != nil {
					return hash, errors.Wrap(err, "submit extrinsic error")
				}
			}
			return hash, nil
		case err = <-sub.Err():
			return hash, errors.Wrap(err, "submit extrinsic error")
		case <-timer.C:
			return hash, errors.Wrap(errors.New("timeout"), "submit extrinsic error")
		}
	}
}

func QueryStorage[T any](c *Client, block uint32, prefix, method string, args ...[]byte) (T, error) {
	var (
		ok   bool
		err  error
		key  types.StorageKey
		data T
	)
	key, err = types.CreateStorageKey(c.Metadata, prefix, method, args...)
	if err != nil {
		return data, errors.Wrap(err, "query storage error")
	}
	if block == 0 {
		ok, err = c.RPC.State.GetStorageLatest(key, &data)
	} else {
		var hash types.Hash
		hash, err = c.RPC.Chain.GetBlockHash(uint64(block))
		if err != nil {
			return data, errors.Wrap(err, "query storage error")
		}
		ok, err = c.RPC.State.GetStorage(key, &data, hash)
	}
	if err != nil {
		return data, errors.Wrap(err, "query storage error")
	}
	if !ok {
		return data, errors.Wrap(errors.New("data not found"), "query storage error")
	}
	return data, nil
}

func QueryStorages[T any](c *Client, block uint32, prefix, method string) ([]T, error) {
	var (
		err   error
		keys  []types.StorageKey
		set   []types.StorageChangeSet
		datas []T
	)
	keys, err = c.RPC.State.GetKeysLatest(createPrefixedKey(method, prefix))
	if err != nil {
		return datas, errors.Wrap(err, "query storages error")
	}
	if block == 0 {
		set, err = c.RPC.State.QueryStorageAtLatest(keys)
	} else {
		var hash types.Hash
		hash, err = c.RPC.Chain.GetBlockHash(uint64(block))
		if err != nil {
			return datas, errors.Wrap(err, "query storages error")
		}
		set, err = c.RPC.State.QueryStorageAt(keys, hash)
	}

	if err != nil {
		return datas, errors.Wrap(err, "query storages error")
	}
	for _, elem := range set {
		for _, change := range elem.Changes {
			var data T
			if err := codec.Decode(change.StorageData, &data); err != nil {
				continue
			}
			datas = append(datas, data)
		}
	}
	return datas, nil
}

func (c *Client) GetCaller(caller *signature.KeyringPair) (signature.KeyringPair, error) {
	var key signature.KeyringPair
	if caller == nil {
		if c.KeyringManager == nil {
			return key, errors.New("invalid tx sender")
		}
		key = c.GetKeyInOrder()
	} else {
		key = *caller
	}
	return key, nil
}

func createPrefixedKey(method, prefix string) []byte {
	return append(xxhash.New128([]byte(prefix)).Sum(nil), xxhash.New128([]byte(method)).Sum(nil)...)
}
