package node

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

type StorageNode struct {
	Account  string `json:"account"`
	Endpoint string `json:"endpoint"`
}

type RetrieverInfo struct {
	Address  string `json:"account"`
	ExtIp    string `json:"ext_ip"`
	Endpoint string `json:"endpoint"`
	Active   bool   `json:"active"`
}

type Retriever struct {
	Info         RetrieverInfo      `json:"info"`
	UpdateAt     time.Time          `json:"update_at"`
	StorageNodes *bloom.BloomFilter `json:"storage_nodes"`
	RetrBytes    uint64             `json:"retr_bytes"`
	RetrTimes    uint64             `json:"retr_times"`
	SendTimes    uint64             `json:"send_times"`
	SendBytes    uint64             `json:"send_bytes"`
	AvgSpeed     uint               `json:"avg_speed"`
	HitRate      float32            `json:"hit_rate"`
}

type Cacher struct {
	Account      string                 `json:"account"`
	ExtIp        string                 `json:"ext_ip"`
	StorageNodes map[string]StorageNode `json:"storage_nodes"`
	AccessOn     time.Time              `json:"access_on"`
	DistTimes    uint64                 `json:"dist_times"`
	DistSucTimes uint64                 `json:"dist_suc_times"`
	RetrTimes    uint64                 `json:"retr_times"`
	RetrSucTimes uint64                 `json:"retr_suc_times"`
}

type NodeManager struct {
	PeerRetrievers          map[string]Retriever
	ActiveCachers           map[string]Cacher
	ActiveStorageNodeFilter *bloom.BloomFilter
	ActiveStorageNodes      *atomic.Int32
	lock                    *sync.RWMutex
}

func NewNodeManager() *NodeManager {
	return &NodeManager{
		PeerRetrievers:          map[string]Retriever{},
		ActiveCachers:           map[string]Cacher{},
		ActiveStorageNodes:      &atomic.Int32{},
		ActiveStorageNodeFilter: bloom.NewWithEstimates(10000, 0.01),
		lock:                    &sync.RWMutex{},
	}
}

func (nm *NodeManager) ExportStorageNodes() []string {
	var nodes []string
	if nm.ActiveCachers == nil {
		return nodes
	}
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	for _, v := range nm.ActiveCachers {
		for k := range v.StorageNodes {
			nodes = append(nodes, k)
		}
	}
	return nodes
}

func (nm *NodeManager) LoadCacher(pubkey []byte) (Cacher, bool) {
	key, err := crypto.DecompressPubkey(pubkey)
	if err != nil {
		return Cacher{}, false
	}
	addr := crypto.PubkeyToAddress(*key).Hex()
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	c, ok := nm.ActiveCachers[addr]
	return c, ok
}

func (nm *NodeManager) LoadRetriever(addr string) (Retriever, bool) {
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	r, ok := nm.PeerRetrievers[addr]
	return r, ok
}

func (nm *NodeManager) SaveOrUpdateRetriever(info RetrieverInfo, storageNodes []string) {
	if len(storageNodes) <= 0 || info.Address == "" || info.Endpoint == "" {
		return
	}
	filter := bloom.NewWithEstimates(uint(len(storageNodes)*3/2), 0.01)
	for _, acc := range storageNodes {
		pk, err := utils.ParsingPublickey(acc)
		if err != nil || len(pk) <= 0 {
			continue
		}
		filter.Add(pk)
	}
	nm.lock.Lock()
	defer nm.lock.Unlock()
	retriever := nm.PeerRetrievers[info.Address]
	retriever.Info = info
	retriever.StorageNodes = filter
	retriever.UpdateAt = time.Now()
	nm.PeerRetrievers[info.Address] = retriever
}

func (nm *NodeManager) SaveOrUpdateCacher(pubkey []byte, extIp string, storageNodes []StorageNode) error {
	if len(pubkey) == 0 || extIp == "" || len(storageNodes) == 0 {
		return nil
	}

	key, err := crypto.DecompressPubkey(pubkey)
	if err != nil {
		return errors.Wrap(err, "save or update cacher error")
	}
	addr := crypto.PubkeyToAddress(*key).Hex()
	nodes := make(map[string]StorageNode)
	for _, node := range storageNodes {
		nodes[node.Account] = node
		pk, err := utils.ParsingPublickey(node.Account)
		if err == nil && len(pk) > 0 {
			nm.ActiveStorageNodeFilter.Add(pk)
		}
	}

	nm.ActiveStorageNodes.Add(int32(len(nodes)))

	nm.lock.Lock()
	defer nm.lock.Unlock()

	cacher := nm.ActiveCachers[addr]
	nm.ActiveStorageNodes.Add(-int32(len(cacher.StorageNodes)))
	cacher.Account = addr
	cacher.ExtIp = extIp
	cacher.StorageNodes = nodes
	cacher.AccessOn = time.Now()
	nm.ActiveCachers[addr] = cacher
	return nil
}

func (nm *NodeManager) CacherDistribution(addr string, success bool) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	cacher, ok := nm.ActiveCachers[addr]
	if !ok {
		return
	}
	if success {
		cacher.DistSucTimes++
	} else {
		cacher.DistTimes++
	}
	nm.ActiveCachers[addr] = cacher
}

func (nm *NodeManager) CacherRetrieval(addr string, success bool) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	cacher, ok := nm.ActiveCachers[addr]
	if !ok {
		return
	}
	if success {
		cacher.RetrSucTimes++
	} else {
		cacher.RetrTimes++
	}
	nm.ActiveCachers[addr] = cacher
}

func (nm *NodeManager) RetrieverSend(addr string, bytes uint64) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	retriever, ok := nm.PeerRetrievers[addr]
	if !ok || bytes == 0 {
		return
	}
	retriever.SendBytes = bytes
	retriever.SendTimes++
	nm.PeerRetrievers[addr] = retriever
}

func (nm *NodeManager) RetrieverReceive(addr string, bytes uint64) {

	nm.lock.Lock()
	defer nm.lock.Unlock()
	retriever, ok := nm.PeerRetrievers[addr]
	if !ok || bytes == 0 {
		return
	}
	retriever.RetrBytes = bytes
	retriever.RetrTimes++
	nm.PeerRetrievers[addr] = retriever
}

func (nm *NodeManager) LocatingResources(storageNodes []string) (Retriever, bool) {
	var (
		count int
		cmap  map[string]int = make(map[string]int)
	)
	nm.lock.RLock()
	defer nm.lock.RUnlock()
	for _, node := range storageNodes {
		pk, err := utils.ParsingPublickey(node)
		if err != nil || len(pk) <= 0 {
			continue
		}
		if nm.ActiveStorageNodeFilter != nil && nm.ActiveStorageNodeFilter.Test(pk) {
			count++
			if count >= 4 {
				return Retriever{}, true
			}
		}
		for k, v := range nm.PeerRetrievers {
			if v.StorageNodes != nil && v.StorageNodes.Test(pk) {
				c := cmap[k]
				c++
				if c >= 4 {
					return v, true
				}
				cmap[k] = c
			}
		}
	}
	return Retriever{}, false
}

// func (nm *NodeManager) LoadRetrieverNodes(cli *chain.Client, contract *evm.CacheProtoContract) error {
// 	conf := config.GetConfig()
// 	// load oss nodes on chain
// 	osses, err := cli.QueryAllOss(0)
// 	if err == nil {
// 		for _, oss := range osses {
// 			endpoint := string(oss.Domain)
// 			if endpoint == "" || endpoint == conf.Endpoint {
// 				continue
// 			}
// 			if !strings.Contains(endpoint, "http://") && !strings.Contains(endpoint, "https://") {
// 				endpoint = fmt.Sprintf("http://%s", endpoint)
// 			}
// 			data, err := client.CheckCdnNodeAvailable(endpoint)
// 			if err != nil {
// 				continue
// 			}

// 		}
// 	}
// }

// osses, err := cli.QueryAllOss(0)
// 	if err != nil {
// 		return errors.Wrap(err, "load oss nodes error")
// 	}
// 	for _, oss := range osses {

// 		node := Cd2nNode{
// 			Cd2nNode: client.Cd2nNode{
// 				EndPoint: string(oss.Domain),
// 			},
// 		}

// 		if node.EndPoint == "" || conf.Endpoint == node.EndPoint {
// 			continue
// 		}
// 		if !strings.Contains(node.EndPoint, "http://") && strings.Contains(node.EndPoint, "https://") {
// 			node.EndPoint = fmt.Sprintf("https://%s", node.EndPoint)
// 		}
// 		data, err := client.CheckCdnNodeAvailable(node.EndPoint)
// 		if err != nil {
// 			//logger.GetLogger(config.LOG_GATEWAY).Error("query cdn node info error ", err.Error())
// 			continue
// 		}
// 		if data.WorkAddr == "" {
// 			data.WorkAddr = hex.EncodeToString(oss.Domain)
// 		}
// 		node.PoolId = data.PoolId
// 		node.IsGateway = data.IsGateway
// 		g.nodes.LoadOrStore(data.WorkAddr, node)
// 		logger.GetLogger(config.LOG_GATEWAY).Info("find a peer retrieval node ", node)
// 	}
