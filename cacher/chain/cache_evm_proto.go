package chain

import (
	"context"
	"math/big"
	"time"

	"github.com/CD2N/CD2N/cacher/chain/contract"
	"github.com/CD2N/CD2N/cacher/logger"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/pkg/errors"
)

const (
	CACHE_PRICE = "1192092895"
)

type NodeInfo struct {
	Created   bool
	Collerate *big.Int
	TokenId   *big.Int
	Endpoint  string
	TeeEth    common.Address
	TeeCess   []byte
}

type Order struct {
	Value   *big.Int
	Creater common.Address
	Node    common.Address
	Term    *big.Int
}

type RegisterReq struct {
	NodeAcc   common.Address
	TokenAcc  common.Address
	TokenId   string
	Endpoint  string
	Signature []byte
	TeeEth    common.Address
	TeeCess   []byte
}

type CacheProtoContract struct {
	Address    common.Address
	Node       common.Address
	NewOption  NewTransactionOption
	LogFilter  LogFilter
	CacheProto *contract.CacheProto
}

func NewProtoContract(cli *ethclient.Client, hexAddr, nodeAcc string, optFunc NewTransactionOption, filter LogFilter) (*CacheProtoContract, error) {
	addr := common.HexToAddress(hexAddr)
	contract, err := contract.NewCacheProto(addr, cli)
	if err != nil {
		return nil, errors.Wrap(err, "new cache protocol evm contract error")
	}
	return &CacheProtoContract{
		Address:    addr,
		LogFilter:  filter,
		Node:       common.HexToAddress(nodeAcc),
		NewOption:  optFunc,
		CacheProto: contract,
	}, nil
}

func (pc *CacheProtoContract) CallFunc(funcName string, args ...any) (any, error) {
	return nil, nil
}

func (pc *CacheProtoContract) QueryRegisterInfo(nodeAcc common.Address) (NodeInfo, error) {
	var info NodeInfo
	info, err := pc.CacheProto.Node(&bind.CallOpts{}, nodeAcc)
	if err != nil {
		return info, errors.Wrap(err, "query node register info error")
	}
	if len(info.Endpoint) == 0 || !info.Created {
		return info, errors.Wrap(errors.New("node not found."), "query node register info error")
	}
	return info, nil
}

func (pc *CacheProtoContract) QueryCdnL1NodeByIndex(index int64) (common.Address, error) {
	addr, err := pc.CacheProto.TeeNodes(&bind.CallOpts{}, big.NewInt(index))
	return addr, errors.Wrap(err, "query cdn L1 node by index error")
}

func (pc *CacheProtoContract) QueryCacheOrder(orderId [32]byte) (Order, error) {
	var order Order
	order, err := pc.CacheProto.Order(&bind.CallOpts{}, orderId)
	if err != nil {
		return order, errors.Wrap(err, "query cache order info error")
	}
	return order, nil
}

func (pc *CacheProtoContract) QueryCurrencyTerm() (*big.Int, error) {

	term, err := pc.CacheProto.GetCurrencyTerm(&bind.CallOpts{})
	if err != nil {
		return nil, errors.Wrap(err, "query currency term error")
	}
	return term, nil
}

func (pc *CacheProtoContract) CreateCacheOrder(ctx context.Context, teeAcc common.Address, traffic string) (string, error) {
	tfValue, ok := big.NewInt(0).SetString(traffic, 10)
	if !ok {
		return "", errors.Wrap(errors.New("bad traffic value"), "create and payment cache order error")
	}
	price, _ := big.NewInt(0).SetString(CACHE_PRICE, 10)

	opts, err := pc.NewOption(ctx, price.Mul(price, tfValue).String())
	if err != nil {
		return "", errors.Wrap(err, "create and payment cache order error")
	}

	tx, err := pc.CacheProto.CacheOrderPayment(opts, teeAcc, tfValue)
	if err != nil {
		return "", errors.Wrap(err, "create and payment cache order error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	if err = pc.LogFilter(
		ctx,
		ethereum.FilterQuery{
			Addresses: []common.Address{pc.Address},
		},
		func(l types.Log) bool {
			event, err := pc.CacheProto.ParseOrderPayment(l)
			if err != nil {
				return true
			}

			if event.TeeAcc == teeAcc {
				return false
			}
			return true
		},
	); err != nil {
		return tx.Hash().Hex(), errors.Wrap(err, "create and payment cache order error")
	}

	return tx.Hash().Hex(), nil
}

func (pc *CacheProtoContract) RegisterNode(ctx context.Context, req RegisterReq) error {
	tokenId, ok := big.NewInt(0).SetString(req.TokenId, 10)
	if !ok {
		return errors.Wrap(errors.New("bad token Id"), "register cache node error")
	}

	opts, err := pc.NewOption(ctx, "")
	if err != nil {
		return errors.Wrap(err, "register cache node error")
	}
	hash, err := pc.CacheProto.Staking(opts, req.NodeAcc, req.TokenAcc, tokenId, req.Endpoint, req.Signature, req.TeeEth, req.TeeCess)
	if err != nil {
		return errors.Wrap(err, "register cache node error")
	}

	logger.GetGlobalLogger().GetLogger("transaction").Debug("register node, tx hash:", hash.Hash())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	if err = pc.LogFilter(
		ctx,
		ethereum.FilterQuery{
			Addresses: []common.Address{pc.Address},
		},
		func(l types.Log) bool {
			event, err := pc.CacheProto.ParseStaking(l)
			if err != nil {
				logger.GetGlobalLogger().GetLogger("transaction").Debug("parse staking event error", err)
				return true
			}
			return event.NodeAcc != req.NodeAcc
		},
	); err != nil {
		return errors.Wrap(err, "register cache node error")
	}
	return nil
}

func (pc *CacheProtoContract) ClaimOrder(ctx context.Context, orderId [32]byte) error {
	opts, err := pc.NewOption(ctx, "")
	if err != nil {
		return errors.Wrap(err, "claim order error")
	}
	_, err = pc.CacheProto.Claim(opts)
	if err != nil {
		return errors.Wrap(err, "claim order error")
	}
	return nil
}

func (pc *CacheProtoContract) ClaimWorkReward(ctx context.Context, nodeAcc common.Address) (string, error) {

	var reward string = "0"
	opts, err := pc.NewOption(ctx, "")
	if err != nil {
		return reward, errors.Wrap(err, "claim work reward error")
	}
	_, err = pc.CacheProto.Claim(opts)
	if err != nil {
		return reward, errors.Wrap(err, "claim work reward error")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()

	if err = pc.LogFilter(
		ctx,
		ethereum.FilterQuery{
			Addresses: []common.Address{pc.Address},
		},
		func(l types.Log) bool {
			event, err := pc.CacheProto.ParseClaim(l)
			if err != nil {
				return true
			}
			if event.NodeAcc == nodeAcc {
				reward = event.Reward.String()
				return false
			}
			return true
		},
	); err != nil {
		return reward, errors.Wrap(err, "claim work reward error")
	}
	return reward, nil
}

func (pc *CacheProtoContract) ClaimWorkRewardServer(ctx context.Context, nodeAcc common.Address) error {

	_, err := pc.QueryRegisterInfo(nodeAcc)
	if err != nil {
		return err
	}
	var term int64 = 1
	ticker := time.NewTicker(time.Hour * 12)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			t, err := pc.QueryCurrencyTerm()
			if err != nil {
				continue
			}
			if t.Int64() <= term {
				continue
			}
			term += 1
			tx, err := pc.ClaimWorkReward(ctx, nodeAcc)
			if err != nil {
				//TODO: print log
				logger.GetGlobalLogger().GetLogger("transaction").Errorf("claim work reward in term %d error %v \n", term, err)
			} else {
				//TODO: print log
				logger.GetGlobalLogger().GetLogger("transaction").Infof("claim work reward in term %d success: %s \n", term, tx)
			}
		}
	}
}

func (pc *CacheProtoContract) ExitNetwork(ctx context.Context, nodeAcc common.Address) error {

	opts, err := pc.NewOption(ctx, "")
	if err != nil {
		return errors.Wrap(err, "node exit network error")
	}
	_, err = pc.CacheProto.Exit(opts)
	if err != nil {
		return errors.Wrap(err, "node exit network error")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
	defer cancel()
	if err = pc.LogFilter(
		ctx,
		ethereum.FilterQuery{
			Addresses: []common.Address{pc.Address},
		},
		func(l types.Log) bool {
			event, err := pc.CacheProto.ParseClaim(l)
			if err != nil {
				return true
			}
			if event.NodeAcc == nodeAcc {
				return false
			}
			return true
		},
	); err != nil {
		return errors.Wrap(err, "node exit network error")
	}
	return nil
}
