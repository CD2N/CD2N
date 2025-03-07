package chain

import (
	"math/rand"

	rpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/retriever"
	"github.com/centrifuge/go-substrate-rpc-client/v4/registry/state"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

type Client struct {
	Rpcs     []string
	mnemonic string
	keypair  signature.KeyringPair
	*rpc.SubstrateAPI
	Retriever retriever.EventRetriever
	Metadata  *types.Metadata
}

type Option func(*Client) error

func RpcAddresses(rpcs []string) Option {
	return func(c *Client) error {
		c.Rpcs = rpcs
		return nil
	}
}

func Mnemonic(mnemonic string) Option {
	return func(c *Client) error {
		var err error
		c.mnemonic = mnemonic
		c.keypair, err = signature.KeyringPairFromSecret(mnemonic, 0)
		return err
	}
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
	client.Retriever, err = retriever.NewDefaultEventRetriever(
		state.NewEventProvider(client.RPC.State),
		client.RPC.State,
	)
	if err != nil {
		return client, errors.Wrap(err, "new cess chain client error")
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
