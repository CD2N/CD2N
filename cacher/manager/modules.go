package manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/pkg/errors"
)

type StoragersManager struct {
	lock      *sync.RWMutex
	storagers []Storage
	smap      map[string]int
	index     int
}

func NewStoragersManager() *StoragersManager {
	return &StoragersManager{
		lock: &sync.RWMutex{},
		smap: make(map[string]int),
	}
}

func (sm *StoragersManager) GetStorager(minerAcc string) (Storage, bool) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()
	if idx, ok := sm.smap[minerAcc]; ok {
		if idx >= 0 && idx < len(sm.storagers) {
			return sm.storagers[idx], true
		}
	}
	for _, storager := range sm.storagers {
		if storager.Account == minerAcc {
			return storager, true
		}
	}
	return Storage{}, false
}

func (sm *StoragersManager) GetMinerEndpoint(dCount uint64) (Endpoint, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	var ep Endpoint
	if len(sm.storagers) == 0 {
		return ep, errors.Wrap(errors.New("no nodes available"), "get miner endpoint error")
	}

	if sm.index < 0 || sm.index > len(sm.storagers) {
		return ep, errors.Wrap(errors.New("node not found"), "get miner endpoint error")
	}
	target := sm.storagers[sm.index]
	if target.Account == "" || target.Endpoint == "" {
		return ep, errors.Wrap(errors.New("no legal storage node"), "get miner endpoint error")
	}
	ep.MinerAcc = target.Account
	ep.MinerAddr = target.Endpoint
	sm.index = (sm.index + 1) % len(sm.storagers)
	return ep, nil
}

func (sm *StoragersManager) LoadStorageNodes(conf config.Config) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()
	var miners config.MinerConfig

	err := config.LoadGeneralConfig(conf.MinerConfigPath, &miners)
	logger.GetLogger(config.LOG_NODE).Info("load storage nodes from ", conf.MinerConfigPath)
	if err != nil {
		return err
	}
	chainCli, err := chain.NewLightCessClient("", conf.Rpcs)
	if err != nil {
		return errors.Wrap(err, "load storage nodes error")
	}
	defer chainCli.Client.Close()
	for _, miner := range conf.StorageNodes {
		acc, err := utils.ParsingPublickey(miner.Account)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		node := Storage{
			Account:  miner.Account,
			Endpoint: miner.Endpoint,
		}
		info, err := chainCli.QueryMinerItems(acc, 0)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		node.TotalSpace = uint64(info.IdleSpace.Int64())
		node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
		node.Available = CheckNodeAvailable(&node)
		sm.storagers = append(sm.storagers, node)
		sm.smap[miner.Account] = len(sm.storagers) - 1
	}

	logger.GetLogger(config.LOG_NODE).Infof("load %d miners from miner config file", len(miners.Miners))

	for _, miner := range miners.Miners {
		endpoint := fmt.Sprintf("http://127.0.0.1:%d", miner.Port)
		keyring, err := signature.KeyringPairFromSecret(miner.Mnemonic, 0)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		acc := utils.EncodePubkey(keyring.PublicKey, conf.Network)
		if _, ok := sm.smap[acc]; ok {
			continue
		}
		node := Storage{
			Account:  acc,
			Endpoint: endpoint,
		}
		info, err := chainCli.QueryMinerItems(keyring.PublicKey, 0)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		node.TotalSpace = uint64(info.IdleSpace.Int64())
		node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
		node.Available = CheckNodeAvailable(&node)
		logger.GetLogger(config.LOG_NODE).Info("load storage ", node.Account, " available? ", node.Available)
		sm.storagers = append(sm.storagers, node)
		sm.smap[acc] = len(sm.storagers) - 1
	}
	return nil
}

func (sm *StoragersManager) UpdateStorageNodeStatus(ctx context.Context, conf config.Config) error {
	ticker := time.NewTicker(time.Minute * 30)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			chainCli, err := chain.NewLightCessClient("", conf.Rpcs)
			if err != nil {
				logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
				continue
			}
			sm.lock.Lock()
			for i, node := range sm.storagers {
				acc, err := utils.ParsingPublickey(node.Account)
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
					continue
				}
				info, err := chainCli.QueryMinerItems(acc, 0)
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
					continue
				}
				node.TotalSpace = uint64(info.IdleSpace.Int64())
				node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
				node.Available = CheckNodeAvailable(&node)
				sm.storagers[i] = node
			}
			sm.lock.Unlock()
			chainCli.Client.Close()
		}
	}
}

// func (m *ProvideManager) UpdateStorageNodeStatus(ctx context.Context, conf config.Config) error {
// 	ticker := time.NewTicker(time.Minute * 30)
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return nil
// 		case <-ticker.C:
// 			chainCli, err := chain.NewLightCessClient("", conf.Rpcs)
// 			if err != nil {
// 				logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
// 				continue
// 			}
// 			m.storagers.Range(func(key, value any) bool {
// 				node := value.(Storage)
// 				acc, err := utils.ParsingPublickey(node.Account)
// 				if err != nil {
// 					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
// 					return true
// 				}
// 				info, err := chainCli.QueryMinerItems(acc, 0)
// 				if err != nil {
// 					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
// 					return true
// 				}
// 				node.TotalSpace = uint64(info.IdleSpace.Int64())
// 				node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
// 				node.Available = CheckNodeAvailable(&node)
// 				m.storagers.Store(key, node)
// 				return true
// 			})
// 			chainCli.Client.Close()
// 		}
// 	}
// }

// func (m *ProvideManager) LoadStorageNodes(conf config.Config) error {
// 	var miners config.MinerConfig

// 	err := config.LoadGeneralConfig(conf.MinerConfigPath, &miners)
// 	logger.GetLogger(config.LOG_NODE).Info("load storage nodes from ", conf.MinerConfigPath)
// 	if err != nil {
// 		return err
// 	}
// 	chainCli, err := chain.NewLightCessClient("", conf.Rpcs)
// 	if err != nil {
// 		return errors.Wrap(err, "load storage nodes error")
// 	}
// 	defer chainCli.Client.Close()
// 	for _, miner := range conf.StorageNodes {
// 		acc, err := utils.ParsingPublickey(miner.Account)
// 		if err != nil {
// 			logger.GetLogger(config.LOG_NODE).Error(err.Error())
// 			continue
// 		}
// 		node := Storage{
// 			Account:  miner.Account,
// 			Endpoint: miner.Endpoint,
// 		}
// 		info, err := chainCli.QueryMinerItems(acc, 0)
// 		if err != nil {
// 			logger.GetLogger(config.LOG_NODE).Error(err.Error())
// 			continue
// 		}
// 		node.TotalSpace = uint64(info.IdleSpace.Int64())
// 		node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
// 		node.Available = CheckNodeAvailable(&node)
// 		m.storagers.Store(miner.Account, node)
// 	}

// 	logger.GetLogger(config.LOG_NODE).Infof("load %d miners from miner config file", len(miners.Miners))

// 	for _, miner := range miners.Miners {
// 		endpoint := fmt.Sprintf("http://127.0.0.1:%d", miner.Port)
// 		keyring, err := signature.KeyringPairFromSecret(miner.Mnemonic, 0)
// 		if err != nil {
// 			logger.GetLogger(config.LOG_NODE).Error(err.Error())
// 			continue
// 		}
// 		acc := utils.EncodePubkey(keyring.PublicKey, conf.Network)
// 		if _, ok := m.storagers.Load(acc); ok {
// 			continue
// 		}
// 		node := Storage{
// 			Account:  acc,
// 			Endpoint: endpoint,
// 		}
// 		info, err := chainCli.QueryMinerItems(keyring.PublicKey, 0)
// 		if err != nil {
// 			logger.GetLogger(config.LOG_NODE).Error(err.Error())
// 			continue
// 		}
// 		node.TotalSpace = uint64(info.IdleSpace.Int64())
// 		node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
// 		node.Available = CheckNodeAvailable(&node)
// 		logger.GetLogger(config.LOG_NODE).Info("load storage ", node.Account, " available? ", node.Available)
// 		m.storagers.Store(acc, node)
// 	}
// 	return nil
// }

// func (m *ProvideManager) GetMinerEndpoint(token string, count uint64) (Endpoint, error) {
// 	var endpoint Endpoint
// 	min, target := 8192000000, Storage{}
// 	tidHash := sha256.Sum256([]byte(token))
// 	m.storagers.Range(func(key, value any) bool {
// 		k := key.(string)
// 		pubkey, err := utils.ParsingPublickey(k)
// 		if err != nil {
// 			return true
// 		}
// 		d := CalcDistance(pubkey, tidHash[:])
// 		if d < min {
// 			node := value.(Storage)
// 			if !node.Available ||
// 				(node.TotalSpace-node.UsedSpace) < count*client.FRAGMENT_SIZE {
// 				return true
// 			}
// 			target = node
// 			min = d
// 			return true
// 		}
// 		return true
// 	})
// 	if target.Account == "" || target.Endpoint == "" {
// 		return endpoint, errors.New("no legal storage node")
// 	}
// 	endpoint.MinerAcc = target.Account
// 	endpoint.MinerAddr = target.Endpoint
// 	return endpoint, nil
// }
