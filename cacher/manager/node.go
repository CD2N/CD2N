package manager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/CD2N/CD2N/cacher/client"
	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/CD2N/CD2N/sdk/sdkgo/chain/evm"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/cache"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/go-redis/redis/v8"
	"github.com/panjf2000/ants/v2"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
)

const (
	NODE_STORAGE = "storage"
	NODE_CDN     = "cdn"
)

type FileInfo struct {
	Fid      string `json:"fid"`
	Storager string `json:"storager"`
}

type Storage struct {
	Account    string `json:"account"`
	TotalSpace uint64 `json:"total_space"`
	UsedSpace  uint64 `json:"used_space"`
	Endpoint   string `json:"endpoint"`
	Available  bool   `json:"available"`
}

func (n *Storage) IsAvailable() bool {
	return n.Available
}

type CdnNode struct {
	Account      string `json:"account"`
	Endpoint     string `json:"endpoint"`
	RedisAddress string `json:"redis_address"`
	TeePubkey    []byte `json:"tee_pubkey"`
	IsGateway    bool   `json:"is_gateway"`
	redisCli     *redis.Client
	Available    bool `json:"available"`
}

func (n *CdnNode) IsAvailable() bool {
	return n.Available
}

type ProvideManager struct {
	files *leveldb.DB
	//cacher.FileCache
	*cache.Cache
	storagers *sync.Map
	cdnNodes  *sync.Map
	staskMap  *sync.Map
	taskChan  chan<- FileTask
	//fileMg    *FileManager
	cli  *evm.CacheProtoContract
	temp string
}

func NewProvideManager(c *cache.Cache, ch chan<- FileTask, cli *evm.CacheProtoContract, fdbPath, tempDir string) (*ProvideManager, error) {
	files, err := client.NewDB(fdbPath)
	if err != nil {
		return nil, errors.Wrap(err, "new provide manager error")
	}
	return &ProvideManager{
		files:     files,
		Cache:     c,
		taskChan:  ch,
		cli:       cli,
		storagers: &sync.Map{},
		cdnNodes:  &sync.Map{},
		staskMap:  &sync.Map{},
		temp:      tempDir,
	}, nil
}

func (m *ProvideManager) ProvideTaskCallback(e Event) {

	if e.Result() == nil {
		logger.GetLogger(config.LOG_TASK).Error("provide task callback: empty result ", e.Error())
		return
	}
	task, ok := e.Result().(*FileProvideTask)
	if !ok {
		logger.GetLogger(config.LOG_TASK).Error("provide task callback: bad task ", e.Error())
		return
	}

	if e.Status() != 200 {
		logger.GetLogger(config.LOG_TASK).Error(e.Error(), " ", e.Result())
		if task.TaskType == TYPE_RETRIEVE {
			if err := client.DeleteData(m.files, task.Did); err != nil {
				logger.GetLogger(config.LOG_TASK).Error(e.Error())
			}
		}
		return
	}

	if task.TaskType == TYPE_RETRIEVE {
		task.TaskType = TYPE_PROVIDE //upgrade task status
		m.taskChan <- task
		return
	}
	if task.TaskType == TYPE_PROVIDE {

		if item := m.Cache.Get(task.Did); item.Value != "" {
			return
		}
		if fs, err := os.Stat(task.Path); err == nil && !fs.IsDir() && fs.Size() > 0 {
			m.Cache.AddWithData(task.Did, task.Path, fs.Size())
		}
	}
}

func (m *ProvideManager) StorageTaskCallback(e Event) {

	if e.Result() == nil {
		logger.GetLogger(config.LOG_TASK).Error("storage task callback: empty result ", e.Error())
		return
	}
	task, ok := e.Result().(*FileStorageTask)
	if !ok {
		logger.GetLogger(config.LOG_TASK).Error("storage task callback: bad storage task ", e.Error())
		return
	}
	if e.Status() != 200 {
		logger.GetLogger(config.LOG_TASK).Error(e.Error())
		if strings.Contains(e.Error().Error(), "timeout") {
			return
		}
		if task.TaskType == TYPE_RETRIEVE && task.Count > len(task.Fragments) {
			//record gateway status
		} else if task.TaskType == TYPE_PROVIDE {
			// record miner status
		}
		return
	}
	var err error
	// idx := len(task.Fragments) - 1
	if task.TaskType == TYPE_RETRIEVE {
		if task.Did == "" {
			if task.Count <= 0 || len(task.Fragments) != task.Count {
				logger.GetLogger(config.LOG_TASK).Error("bad task: ", task.String())
				return
			}
			task.Sign = ""
			task.Did = task.Fragments[0]
			task.Fragments = task.Fragments[1:]
			task.Path = path.Join(m.temp, task.Fid, task.Did)
			dir := path.Join(m.temp, task.Fid)
			if _, err := os.Stat(dir); err != nil {
				err = os.MkdirAll(dir, 0755)
				if err != nil {
					logger.GetLogger(config.LOG_TASK).Error(e.Error())
					return
				}
			}
			m.taskChan <- task // start fetch fragments from gateway
			return
		}
		task.TaskType = TYPE_PROVIDE
		if task.MinerAcc == "" || task.MinerAddr == "" {
			task.Endpoint, err = m.GetMinerEndpoint(task.Token, uint64(task.Count))
			if err != nil {
				logger.GetLogger(config.LOG_TASK).Error(e.Error())
				return
			}
			//Redistribute data
			m.CopyAndStoreStorageTask(task)
		}
		m.taskChan <- task
		return
	}
	if task.TaskType == TYPE_PROVIDE {
		if err = client.PutData(m.files, task.Did, FileInfo{
			Storager: task.MinerAcc,
			Fid:      task.Fid,
		}); err != nil {
			logger.GetLogger(config.LOG_TASK).Error(e.Error())
		}
		if len(task.Fragments) <= 0 {
			//TODO: report status
			logger.GetLogger(config.LOG_TASK).Infof("task %s done, fid: %s", task.Tid, task.Fid)
			return
		}
		if item := m.Cache.Get(task.Did); item.Key == "" || item.Value == "" {
			if fs, err := os.Stat(task.Path); err == nil && !fs.IsDir() && fs.Size() > 0 {
				m.Cache.AddWithData(task.Did, task.Path, fs.Size())
			}
		}
		task.Did = task.Fragments[0]
		task.Path = path.Join(m.temp, task.Fid, task.Did)
		task.Fragments = task.Fragments[1:]
		task.TaskType = TYPE_RETRIEVE
		m.taskChan <- task
	}
}

func (m *ProvideManager) CopyAndStoreStorageTask(ft *FileStorageTask) {
	newFt := &FileStorageTask{
		Task:      ft.Task,
		Callback:  ft.Callback,
		TaskType:  ft.TaskType,
		Endpoint:  ft.Endpoint,
		Fid:       ft.Fid,
		Count:     ft.Count,
		Fragments: ft.Fragments,
	}
	m.staskMap.LoadOrStore(ft.Tid, newFt)
}

func (m *ProvideManager) StorageTaskChecker(ctx context.Context) error {
	net := config.GetConfig().Network
	ticker := time.NewTicker(time.Minute * 15)
	for {
		select {
		case <-ticker.C:
			chainCli, err := chain.NewLightCessClient("", config.GetConfig().Rpcs)
			if err != nil {
				logger.GetLogger(config.LOG_NODE).Error("new cess chain client error", err)
				continue
			}
			m.staskMap.Range(func(key, value any) bool {
				task := value.(*FileStorageTask)
				order, err := chainCli.QueryDealMap(task.Fid, 0)
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("check storage order error", err)
					return true
				}
				for _, c := range order.CompleteList {
					acc := utils.EncodePubkey(c.Miner[:], net)
					if acc == task.MinerAcc {
						m.staskMap.Delete(key)
						return true
					}
				}
				task.Endpoint, err = m.GetMinerEndpoint(task.Token+"tag:redistribution", uint64(task.Count))
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("check storage order error", err)
					return true
				}
				m.taskChan <- task
				return true
			})
			chainCli.Client.Close()
		case <-ctx.Done():
			return errors.New("context done")
		}
	}
}

func (m *ProvideManager) GetMinerEndpoint(token string, count uint64) (Endpoint, error) {
	var endpoint Endpoint
	min, target := 8192000000, Storage{}
	tidHash := sha256.Sum256([]byte(token))
	m.storagers.Range(func(key, value any) bool {
		k := key.(string)
		pubkey, err := utils.ParsingPublickey(k)
		if err != nil {
			return true
		}
		d := CalcDistance(pubkey, tidHash[:])
		if d < min {
			node := value.(Storage)
			if !node.Available ||
				(node.TotalSpace-node.UsedSpace) < count*client.FRAGMENT_SIZE {
				return true
			}
			target = node
			min = d
			return true
		}
		return true
	})
	if target.Account == "" || target.Endpoint == "" {
		return endpoint, errors.New("no legal storage node")
	}
	endpoint.MinerAcc = target.Account
	endpoint.MinerAddr = target.Endpoint
	return endpoint, nil
}

func (m *ProvideManager) GetFileInfo(did, fid string, net uint16) (FileInfo, error) {
	var finfo FileInfo
	err := client.GetData(m.files, did, &finfo)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	if finfo.Storager != "" {
		return finfo, nil
	}
	if fid == "" {
		return finfo, errors.Wrap(errors.New("file info not found"), "get file info error")
	}
	chainCli, err := chain.NewLightCessClient("", config.GetConfig().Rpcs)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	fmeta, err := chainCli.QueryFileMetadata(fid, 0)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	for _, seg := range fmeta.SegmentList {
		for _, frag := range seg.FragmentList {
			if string(frag.Hash[:]) != did {
				continue
			}
			minerAcc := utils.EncodePubkey(frag.Miner[:], net)
			if _, ok := m.storagers.Load(minerAcc); ok {
				finfo.Fid = fid
				finfo.Storager = minerAcc
				return finfo, nil
			}
		}
	}
	return finfo, errors.Wrap(errors.New("file info not found"), "get file info error")
}

func (m *ProvideManager) ExecuteTasks(ctx context.Context, taskCh <-chan *redis.Message) error {
	net := config.GetConfig().Network
	for {
		select {
		case <-ctx.Done():
			return nil
		case task := <-taskCh:
			var taskPld Task
			logger.GetLogger(config.LOG_TASK).Infof("subscribe task from channel: %s", task.Channel)
			err := json.Unmarshal([]byte(task.Payload), &taskPld)
			if err != nil {
				logger.GetLogger(config.LOG_TASK).Error(err.Error())
				continue
			}

			if task.Channel == client.CHANNEL_PROVIDE {
				ftask := &FileStorageTask{
					Task:     taskPld,
					Fid:      taskPld.Did,
					Path:     path.Join(m.temp, taskPld.Did),
					TaskType: TYPE_RETRIEVE,
					Callback: m.StorageTaskCallback,
				}
				ftask.Did = ""
				m.taskChan <- ftask
				continue
			}
			if task.Channel == client.CHANNEL_RETRIEVE {

				nv, ok := m.cdnNodes.Load(taskPld.Acc)
				if !ok {
					logger.GetLogger(config.LOG_TASK).Error("cdn node not be found.")
					continue
				}
				cdnNode := nv.(CdnNode)

				finfo, err := m.GetFileInfo(taskPld.Did, taskPld.ExtData, net)
				if err != nil {
					logger.GetLogger(config.LOG_TASK).Error(err.Error())
					continue
				}
				if item := m.Cache.Get(taskPld.Did); item.Value != "" {
					m.taskChan <- &FileProvideTask{
						Task:      taskPld,
						TaskType:  TYPE_PROVIDE,
						Path:      item.Value,
						TeePubkey: cdnNode.TeePubkey,
						Callback:  m.ProvideTaskCallback,
					}
					continue
				}
				value, ok := m.storagers.Load(finfo.Storager)
				if !ok {
					logger.GetLogger(config.LOG_TASK).Error("storage node not be found.")
					continue
				}
				node := value.(Storage)
				m.taskChan <- &FileProvideTask{
					Task:      taskPld,
					TaskType:  TYPE_RETRIEVE,
					TeePubkey: cdnNode.TeePubkey,
					Path:      path.Join(m.temp, taskPld.Did),
					Endpoint: Endpoint{
						MinerAcc:  finfo.Storager,
						MinerAddr: node.Endpoint,
					},
					Fid:      finfo.Fid,
					Callback: m.ProvideTaskCallback,
				}
			}
		}
	}
}

func (m *ProvideManager) LoadStorageNodes(conf config.Config) error {
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
		m.storagers.Store(miner.Account, node)
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
		if _, ok := m.storagers.Load(acc); ok {
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
		m.storagers.Store(acc, node)
	}
	return nil
}

func (m *ProvideManager) LoadCdnNodes(conf config.Config) error {
	for _, cdn := range conf.CdnNodes {
		if cdn.Account == "" || cdn.Endpoint == "" {
			continue
		}
		node := CdnNode{
			Account:  cdn.Account,
			Endpoint: cdn.Endpoint,
		}
		ava := CheckNodeAvailable(&node)
		node.Available = ava
		actl, ok := m.cdnNodes.LoadOrStore(cdn.Account, node)
		if ok {
			node = actl.(CdnNode)
			if !node.Available && ava {
				node.Available = true
				m.cdnNodes.Store(cdn.Account, node)
			}
		}
	}
	var index int64
	for {
		addr, err := m.cli.QueryCdnL1NodeByIndex(index)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error("query cdn node info error ", err.Error())
			break
		}
		index++
		info, err := m.cli.QueryRegisterInfo(addr)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error("query cdn node info error ", err.Error())
			continue
		}
		node := CdnNode{
			Account:  addr.Hex(),
			Endpoint: info.Endpoint,
		}
		node.Available = CheckNodeAvailable(&node)
		m.cdnNodes.LoadOrStore(node.Account, node)
	}
	return nil
}

func (m *ProvideManager) UpdateStorageNodeStatus(ctx context.Context, conf config.Config) error {
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
			m.storagers.Range(func(key, value any) bool {
				node := value.(Storage)
				acc, err := utils.ParsingPublickey(node.Account)
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
					return true
				}
				info, err := chainCli.QueryMinerItems(acc, 0)
				if err != nil {
					logger.GetLogger(config.LOG_NODE).Error("update storage status error ", err.Error())
					return true
				}
				node.TotalSpace = uint64(info.IdleSpace.Int64())
				node.UsedSpace = uint64(info.ServiceSpace.Int64() + info.LockSpace.Int64())
				node.Available = CheckNodeAvailable(&node)
				m.storagers.Store(key, node)
				return true
			})
			chainCli.Client.Close()
		}
	}
}

func (m *ProvideManager) SubscribeMessageFromCdnNodes(ctx context.Context, taskCh chan<- *redis.Message, channels ...string) error {
	m.cdnNodes.Range(func(key, value any) bool {
		node := value.(CdnNode)
		if node.RedisAddress != "" && node.redisCli == nil {
			node.redisCli = client.NewRedisClient(node.RedisAddress, "provider", "cd2n.provider")
			ants.Submit(func() { client.SubscribeMessage(node.redisCli, ctx, taskCh, channels...) })
			m.cdnNodes.Store(key, node)
		}
		return true
	})
	return nil
}

func CalcDistance(a, b []byte) int {
	dist := 1
	for i := 0; i < len(a) && i < len(b); i++ {
		d := a[i] ^ b[i]
		dist += int(d) * (i + 1)
	}
	return dist
}

func CheckNodeAvailable(node any) bool {
	switch n := node.(type) {
	case *Storage:
		return client.CheckStorageNodeAvailable(n.Endpoint) == nil
	case *CdnNode:
		info, err := client.CheckCdnNodeAvailable(n.Endpoint)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error("check cdn node available error ", err.Error())
			return false
		}
		n.TeePubkey = info.TeePubkey
		n.IsGateway = info.IsGateway
		n.RedisAddress = info.RedisAddr
	}
	return false
}
