package manager

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CD2N/CD2N/cacher/chain"
	"github.com/CD2N/CD2N/cacher/client"
	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CD2N/CD2N/cacher/logger"
	"github.com/CD2N/CD2N/cacher/utils"
	"github.com/CESSProject/cess-go-tools/cacher"
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
	cacher.FileCache
	storagers *sync.Map
	cdnNodes  *sync.Map
	missFiles *sync.Map
	taskChan  chan<- FileTask
	//fileMg    *FileManager
	cli  *chain.CacheProtoContract
	temp string
}

func NewProvideManager(c cacher.FileCache, ch chan<- FileTask, cli *chain.CacheProtoContract, fdbPath, tempDir string) (*ProvideManager, error) {
	files, err := client.NewDB(fdbPath)
	if err != nil {
		return nil, errors.Wrap(err, "new provide manager error")
	}
	return &ProvideManager{
		files:     files,
		FileCache: c,
		taskChan:  ch,
		cli:       cli,
		storagers: &sync.Map{},
		cdnNodes:  &sync.Map{},
		missFiles: &sync.Map{},
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
		logger.GetLogger(config.LOG_TASK).Error(e.Error())
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
		if fpath, err := m.FileCache.GetCacheRecord(task.Did); err == nil && fpath != "" {
			return
		}
		if err := m.FileCache.MoveFileToCache(task.Did, task.Path); err != nil {
			logger.GetLogger(config.LOG_TASK).Error(e.Error())
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
		m.FileCache.MoveFileToCache(task.Did, task.Path)
		task.Did = task.Fragments[0]
		task.Path = path.Join(m.temp, task.Fid, task.Did)
		task.Fragments = task.Fragments[1:]
		task.TaskType = TYPE_RETRIEVE
		m.taskChan <- task
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

func (m *ProvideManager) GetFileInfo(did, fid string) (FileInfo, error) {
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
	chainCli, err := chain.NewCessChainClient(context.Background(), config.GetConfig().Rpcs)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	fmeta, err := chainCli.QueryFile(fid, -1)
	if err != nil {
		return finfo, errors.Wrap(err, "get file info error")
	}
	for _, seg := range fmeta.SegmentList {
		for _, frag := range seg.FragmentList {
			if string(frag.Hash[:]) != did {
				continue
			}
			minerAcc, err := utils.EncodePublicKeyAsCessAccount(frag.Miner[:])
			if err != nil {
				logger.GetLogger(config.LOG_TASK).Error("encode miner pubkey error ", err)
				continue
			}
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

				finfo, err := m.GetFileInfo(taskPld.Did, taskPld.ExtData)
				if err != nil {
					logger.GetLogger(config.LOG_TASK).Error(err.Error())
					continue
				}
				if fpath, err := m.FileCache.GetCacheRecord(taskPld.Did); err == nil {
					m.taskChan <- &FileProvideTask{
						Task:      taskPld,
						TaskType:  TYPE_PROVIDE,
						Path:      fpath,
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
	chainCli, err := chain.NewCessChainClient(context.Background(), conf.Rpcs)
	if err != nil {
		return errors.Wrap(err, "load storage nodes error")
	}
	defer chainCli.Close()
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
		info, err := chainCli.QueryMinerItems(acc, -1)
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
		acc, err := utils.EncodePublicKeyAsCessAccount(keyring.PublicKey)
		if err != nil {
			logger.GetLogger(config.LOG_NODE).Error(err.Error())
			continue
		}
		if _, ok := m.storagers.Load(acc); ok {
			continue
		}
		node := Storage{
			Account:  acc,
			Endpoint: endpoint,
		}
		info, err := chainCli.QueryMinerItems(keyring.PublicKey, -1)
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
		node.Available = CheckNodeAvailable(&node)
		m.cdnNodes.LoadOrStore(cdn.Account, node)
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
			chainCli, err := chain.NewCessChainClient(context.Background(), conf.Rpcs)
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
				info, err := chainCli.QueryMinerItems(acc, -1)
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
			chainCli.Close()
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

func (m *ProvideManager) RestoreCacheFiles(cacheDir string) error {
	return filepath.Walk(cacheDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Size() == client.FRAGMENT_SIZE {
			paths := strings.Split(path, "/")
			l := len(paths)
			if l < 4 {
				return nil
			}
			m.FileCache.AddCacheRecord(filepath.Join(paths[l-1], paths[l-2], paths[l-3]), path)
		} else if info.Size() > 0 {
			m.FileCache.AddCacheRecord(info.Name(), path)
		}
		logger.GetLogger(config.LOG_NODE).Info("restore file ", path)
		return nil
	})
}
