package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/logger"
	"github.com/CD2N/CD2N/retriever/node"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/pkg/errors"
)

func (g *Gateway) batchRetriever(ctx context.Context, indicators int, handle func(context.Context, string) (string, error), dataIds ...string) []string {
	if indicators <= 0 {
		indicators = 4
	}
	subWg := &sync.WaitGroup{}
	pathSet, pathCount := &sync.Map{}, &atomic.Int32{}
	for i, did := range dataIds {
		subWg.Add(1)

		err := g.pool.Submit(func() {
			defer subWg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				rpath, err := handle(ctx, did)
				if err != nil {
					logger.GetLogger(config.LOG_GATEWAY).Error("batch retrieval data error  ", err)
					return
				}
				pathSet.Store(rpath, struct{}{})
				pathCount.Add(1)
			}
		})
		if err != nil {
			logger.GetLogger(config.LOG_GATEWAY).Error("batch retrieval data error  ", err)
		}
		if i > 0 && (i+1)%indicators == 0 {
			subWg.Wait()
			if pathCount.Load() >= int32(indicators) {
				logger.GetLogger(config.LOG_GATEWAY).Info("batch retrieve success")
				break
			}
			subWg = &sync.WaitGroup{}
		}
	}
	subWg.Wait()
	var paths []string
	pathSet.Range(func(key, value any) bool {
		paths = append(paths, key.(string))
		return true
	})
	return paths
}

func (g *Gateway) RetrieveDatasInLocal(cdn node.Cd2nNode, exp time.Duration, dids ...string) []string {
	ctx, cancel := context.WithTimeout(context.Background(), exp)
	defer cancel()
	return g.batchRetriever(ctx, config.FRAGMENTS_NUM,
		func(ctx context.Context, did string) (string, error) {

			cid, err := cdn.GetDataCid(did)
			if err != nil && cid == "" {
				return "", errors.Wrap(err, "retrieve data in local error")
			}
			rpath, err := cdn.RetrieveLocalData(ctx, cid)
			return rpath, errors.Wrap(err, "retrieve data in local error")
		},
		dids...,
	)
}

func (g *Gateway) RetrieveDatasInPool(cdn node.Cd2nNode, buf *buffer.FileBuffer, exp time.Duration, teeUrl, poolId, fid string, dids ...string) []string {
	var (
		nodes []Cd2nNode
	)
	g.nodes.Range(func(key, value any) bool {
		node := value.(Cd2nNode)
		if node.PoolId == poolId {
			nodes = append(nodes, node)
		}
		return true
	})

	nodeNum := len(nodes)
	ctx, cancel := context.WithTimeout(context.Background(), exp*2)
	defer cancel()

	return g.batchRetriever(ctx, config.FRAGMENTS_NUM,
		func(ctx context.Context, did string) (string, error) {
			var (
				rpath string
				err   error
			)
			ctx, cancel := context.WithTimeout(ctx, exp)
			defer cancel()

			idx := rand.IntN(nodeNum + 1)
			if idx >= nodeNum {
				reqId, sign, err := g.SignRequestTool()
				if err != nil {
					return rpath, errors.Wrap(err, "retrieve data in pool error")
				}
				rpath, err = cdn.RetrieveDataService(ctx, teeUrl, g.contract.Node.Hex(), reqId, fid, exp, did, sign)
				// if err == nil && rpath != "" {
				// 	return rpath, nil
				// }
				return rpath, errors.Wrap(err, "retrieve data in pool error")
			}

			rNode := nodes[idx]
			rpath, err = buf.NewBufPath(poolId, did)
			if err != nil {
				return "", errors.Wrap(err, "retrieve data in pool error")
			}
			err = g.CheckAndCreateOrder(ctx, rNode, fmt.Sprint(config.GetConfig().RechargeSize))
			if err != nil {
				return "", errors.Wrap(err, "retrieve data in pool error")
			}
			err = g.GetDataFromRemote(did, rpath, rNode)
			if err != nil {
				return "", errors.Wrap(err, "retrieve data in pool error")
			}
			buf.AddData(did, rpath)
			return rpath, errors.Wrap(err, "retrieve data in pool error")
		},
		dids...,
	)
}

func (g *Gateway) QueryDataFrom(segment string) []Cd2nNode {
	var (
		nodes  []Cd2nNode
		poolId string
		lock   = &sync.RWMutex{}
	)

	g.nodes.Range(func(key, value any) bool {
		node := value.(Cd2nNode)
		u, err := url.JoinPath(node.EndPoint, client.QUERY_DATA_INFO_URL, segment)
		if err != nil {
			return true //continue
		}
		lock.RLock()
		if poolId != "" {
			if poolId == node.PoolId {
				nodes = append(nodes, node)
			}
			lock.RUnlock()
			return true
		}
		lock.RUnlock()
		g.pool.Submit(func() {
			if !node.IsGateway {
				return
			}
			respBytes, err := client.SendHttpRequest(http.MethodGet, u, nil, nil)
			if err != nil {
				return
			}
			var resp client.Response
			err = json.Unmarshal(respBytes, &resp)
			if err != nil {
				return
			}
			if resp.Code != http.StatusOK {
				return
			}
			lock.Lock()
			if poolId != "" {
				if poolId == node.PoolId {
					nodes = append(nodes, node)
				}
				lock.Unlock()
				return
			}
			nodes = append(nodes, node)
			poolId = node.PoolId
			lock.Unlock()
		})
		return true
	})

	return nodes
}

func (g *Gateway) RetrieveDataFromRemote(ctx context.Context, nodes []Cd2nNode, buf *buffer.FileBuffer, fid string, dids ...string) []string {
	nodeNum := len(nodes)
	if nodeNum <= 0 {
		return nil
	}
	return g.batchRetriever(ctx, config.FRAGMENTS_NUM,
		func(ctx context.Context, did string) (string, error) {
			rNode := nodes[rand.IntN(nodeNum)]
			fpath, err := buf.NewBufPath(did)
			if err != nil {
				return "", err
			}
			err = g.CheckAndCreateOrder(ctx, rNode, fmt.Sprint(config.GetConfig().RechargeSize))
			if err != nil {
				return "", errors.Wrap(err, "retrieve data from remote  error")
			}
			err = g.GetDataFromRemote(did, fpath, rNode)
			if err != nil {
				return "", err
			}
			buf.AddData(did, fpath)
			return fpath, nil
		})
}

func (g *Gateway) GetDataInfo(segment string) (DataRecord, error) {
	var record DataRecord
	err := client.GetData(g.taskRecord, config.DB_SEGMENT_PREFIX+segment, &record)
	if err != nil {
		return record, errors.Wrap(err, "get data info error")
	}
	return record, nil
}

func (g *Gateway) SaveDataInfo(segment string, fragments []string) error {
	err := client.PutData(g.taskRecord, config.DB_SEGMENT_PREFIX+segment, DataRecord{Fragments: fragments})
	return errors.Wrap(err, "save data info error")
}

func (g *Gateway) GetDataFromRemote(did, fpath string, node Cd2nNode) error {
	u, err := url.JoinPath(node.EndPoint, client.FETCH_CACHE_DATA_URL, did, g.contract.Node.Hex())
	if err != nil {
		return errors.Wrap(err, "retrieve data from remote  error")
	}
	reqId, sign, err := g.SignRequestTool()
	if err != nil {
		return errors.Wrap(err, "retrieve data from remote  error")
	}
	req := client.CacheRequest{
		Did:       did,
		UserAddr:  g.contract.Node.Hex()[2:],
		Sign:      sign,
		Exp:       int64(time.Second * 12),
		RequestId: reqId,
	}
	jbytes, err := json.Marshal(req)
	if err != nil {
		return errors.Wrap(err, "retrieve data from remote  error")
	}
	headers := map[string]string{"Content-Type": "application/json"}
	bytes, err := client.SendHttpRequest(http.MethodPost, u, headers, bytes.NewBuffer(jbytes))
	if err != nil {
		return errors.Wrap(err, "retrieve data from remote error")
	}
	f, err := os.Create(fpath)
	if err != nil {
		return errors.Wrap(err, "retrieve data from remote  error")
	}
	defer f.Close()
	_, err = f.Write(bytes)
	return errors.Wrap(err, "retrieve data from remote  error")
}

func (g *Gateway) SignRequestTool() (string, []byte, error) {
	reqIdBytes, err := utils.GetRandomBytes()
	if err != nil {
		return "", nil, err
	}
	reqId := hex.EncodeToString(reqIdBytes)
	sign, err := g.contract.Signature([]byte(reqId))
	if err != nil {
		return "", nil, err
	}
	return reqId, sign, nil
}
