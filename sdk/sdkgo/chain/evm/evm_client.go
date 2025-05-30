package evm

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/pkg/errors"
)

type Contract interface {
	CallFunc(funcName string, args ...any) (any, error)
}

type NewTransactionOption func(ctx context.Context, value string) (*bind.TransactOpts, error)
type LogFilter[T any] func(ctx context.Context, t T, callback func(types.Log) bool) error

type Client struct {
	RpcAddrs  []string
	ChainID   int64
	GasFeeCap *big.Int
	GasLimit  uint64
	cli       *ethclient.Client
	rpcErrCh  chan error
	Account   common.Address
	sk        *ecdsa.PrivateKey
	Contracts map[string]Contract
}

type Option func(*Client) error

func NewClient(opts ...Option) (*Client, error) {
	cli := &Client{
		rpcErrCh:  make(chan error),
		Contracts: make(map[string]Contract),
	}
	for _, opt := range opts {
		err := opt(cli)
		if err != nil {
			return cli, errors.Wrap(err, "new ethereum client error")
		}
	}
	if len(cli.RpcAddrs) == 0 {
		err := errors.New("no RPC address is configured")
		return cli, errors.Wrap(err, "new ethereum client error")
	}
	for _, rpc := range cli.RpcAddrs {
		client, err := ethclient.Dial(rpc)
		if err == nil {
			cli.cli = client
			break
		}
	}
	if cli.cli == nil {
		err := errors.New("chain RPC connection failed")
		return cli, errors.Wrap(err, "new ethereum client error")
	}
	if cli.GasFeeCap == nil {
		cli.GasFeeCap = big.NewInt(108694000460)
	}
	if cli.GasLimit == 0 {
		cli.GasLimit = uint64(30000000)
	}
	return cli, nil
}

func ConnectionRpcAddresss(rpcs []string) Option {
	return func(c *Client) error {
		if len(rpcs) == 0 {
			return errors.New("empty rpc address list")
		}
		c.RpcAddrs = rpcs
		return nil
	}
}

func NodeEthAccount(hexAcc string) Option {
	return func(c *Client) error {
		c.Account = common.HexToAddress(hexAcc)
		return nil
	}
}

func ChainID(id int64) Option {
	return func(c *Client) error {
		c.ChainID = id
		return nil
	}
}

func EthereumGas(gasFeeCap int64, gasLimit uint64) Option {
	return func(c *Client) error {
		c.GasFeeCap = big.NewInt(gasFeeCap)
		c.GasLimit = gasLimit
		return nil
	}
}

func AccountPrivateKey(hexKey string) Option {
	return func(c *Client) error {
		sk, err := crypto.HexToECDSA(hexKey)
		if err != nil {
			return err
		}

		c.Account = crypto.PubkeyToAddress(sk.PublicKey)

		c.sk = sk
		return nil
	}
}

func (cli *Client) UpdateClient() error {
	update := false
	for _, rpc := range cli.RpcAddrs {
		client, err := ethclient.Dial(rpc)
		if err == nil {
			cli.cli = client
			update = true
			break
		}
	}
	if !update {
		return errors.New("chain RPC connection failed")
	}
	return nil
}

func (cli *Client) AddWorkContract(name string, contract Contract) {
	cli.Contracts[name] = contract
}

func (cli Client) GetContractAddress(name string) Contract {
	return cli.Contracts[name]
}

func (cli Client) GetPrivateKey() ecdsa.PrivateKey {
	return *cli.sk
}

func (cli Client) GetEthClient() *ethclient.Client {
	return cli.cli
}

func (cli Client) VerifySign(data []byte, sign []byte) bool {
	hash := sha256.New()
	hash.Write(data)
	return crypto.VerifySignature(
		crypto.CompressPubkey(&cli.sk.PublicKey),
		hash.Sum(nil), sign,
	)
}

func (cli Client) GetSignature(data []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(data)
	return crypto.Sign(hash.Sum(nil), cli.sk)
}

func (cli Client) NewTransactionOption(ctx context.Context, value string) (*bind.TransactOpts, error) {
	gasTipCap, _ := cli.cli.SuggestGasTipCap(ctx)
	opts, err := bind.NewKeyedTransactorWithChainID(cli.sk, big.NewInt(11330))
	if err != nil {
		return nil, errors.Wrap(err, "new transaction option error")
	}
	opts.GasTipCap = gasTipCap
	opts.GasFeeCap = cli.GasFeeCap
	opts.GasLimit = cli.GasLimit
	if value != "" {
		opts.Value, _ = big.NewInt(0).SetString(value, 10)
	}
	return opts, nil
}

func (cli Client) ParsingTransactionLogs(ctx context.Context, tx *types.Transaction, callback func(types.Log) bool) error {
	log.Println("parse tx hash", tx.Hash().Hex())
	receipt, err := cli.cli.TransactionReceipt(ctx, tx.Hash())
	if err != nil {
		return errors.Wrap(err, "parsing tranaction logs error")
	}
	log.Println("parsed logs", receipt)
	for _, txlog := range receipt.Logs {
		if !callback(*txlog) {
			break
		}
	}

	return nil
}

func (cli Client) SubscribeFilterLogs(ctx context.Context, q ethereum.FilterQuery, callback func(types.Log) bool) error {
	ch := make(chan types.Log)
	nowBlock, err := cli.cli.BlockNumber(ctx)
	if err != nil {
		return err
	}
	log.Println("now block:", nowBlock)
	q.FromBlock = big.NewInt(0).SetUint64(nowBlock - 15)
	q.ToBlock = big.NewInt(0).SetUint64(nowBlock)
	sub, err := cli.cli.SubscribeFilterLogs(ctx, q, ch)
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	loop := true
	for loop {
		select {
		case log := <-ch:
			loop = callback(log)
		case err = <-sub.Err():
			return err
		case <-ctx.Done():
			return errors.New("timeout")
		}
	}
	return nil
}
