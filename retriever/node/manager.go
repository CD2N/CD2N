package node

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/CD2N/CD2N/retriever/libs/buffer"
	"github.com/CD2N/CD2N/retriever/libs/cache"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/go-redis/redis/v8"
	"github.com/ipfs/kubo/client/rpc"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
)

type Cd2nNode interface {
	GetDataCid(dataId string) (string, error)
	RetrieveLocalData(ctx context.Context, cid string) (string, error)
	GetRetrieveTask(ctx context.Context, tid string) (task.RetrieveTask, error)
	ReceiveData(ctx context.Context, tid, provider, fpath string, pubkey []byte) error
	RetrieveDataService(ctx context.Context, teeUrl, user, reqId, extdata string, exp time.Duration, did string, sign []byte) (string, error)
}

type Manager struct {
	redisCli  *redis.Client
	ipfsCli   *rpc.HttpApi
	cidRecord *leveldb.DB
	nodeAddr  string
	databuf   *buffer.FileBuffer
	cacher    *cache.Cache

	rtasks     map[string]chan string
	callbackCh chan string
	rw         *sync.RWMutex
}

func NewManager(redisCli *redis.Client, ipfsCli *rpc.HttpApi, cidrecord *leveldb.DB, cacher *cache.Cache, buf *buffer.FileBuffer, nodeAddr string) *Manager {

	mg := &Manager{
		redisCli:   redisCli,
		ipfsCli:    ipfsCli,
		cidRecord:  cidrecord,
		rtasks:     make(map[string]chan string),
		callbackCh: make(chan string, task.CALLBACK_CHANNEL_SIZE),
		nodeAddr:   nodeAddr,
		cacher:     cacher,
		databuf:    buf,
		rw:         &sync.RWMutex{},
	}
	return mg
}

func (mg *Manager) SubscribeCidMap(ctx context.Context, key string) error {
	err := client.SubscribeMessageInIpfs(mg.ipfsCli, ctx, key,
		func(b []byte) {
			var mp client.CidMap
			err := json.Unmarshal(b, &mp)
			if err != nil {
				return
			}
			ok, err := mg.cidRecord.Has([]byte(mp.Did), nil)
			if err != nil {
				return
			}
			if !ok && mp.Did != "" && mp.Cid != "" {
				client.PutData(mg.cidRecord, mp.Did, mp.Cid)
			}
		},
	)
	return errors.Wrap(err, "subscribe cid map error")
}

func (mg *Manager) PublishCidMap(ctx context.Context, key, did, cid string) error {
	jbytes, err := json.Marshal(client.CidMap{Cid: cid, Did: did})
	if err != nil {
		return errors.Wrap(err, "publish cid map error")
	}
	err = client.PubMessageInIpfs(mg.ipfsCli, ctx, key, jbytes)
	return errors.Wrap(err, "publish cid map error")
}

func (mg *Manager) GetNodeAddress() string {
	return mg.nodeAddr
}
