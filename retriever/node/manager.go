package node

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/buffer"
	"github.com/go-redis/redis/v8"
	"github.com/syndtr/goleveldb/leveldb"
)

type Cd2nNode interface {
	GetDataCid(dataId string) (string, error)
	//RetrieveLocalData(ctx context.Context, cid string) (string, error)
	GetRetrieveTask(ctx context.Context, tid string) (task.RetrieveTask, error)
	ReceiveData(ctx context.Context, tid, provider, fpath string, pubkey []byte) error
	RetrieveDataService(ctx context.Context, teeUrl, user, reqId, extdata string, exp time.Duration, did string, sign []byte) (string, error)
}

type Status struct {
	Address      string
	NTBR         uint64
	RetrieveNum  uint64
	RetrievedNum uint64
}

type Manager struct {
	redisCli     *redis.Client
	cidRecord    *leveldb.DB
	nodeAddr     string
	databuf      *buffer.FileBuffer
	retrieveNum  *atomic.Uint64
	retrievedNum *atomic.Uint64
	rtasks       map[string]chan string
	callbackCh   chan string
	rw           *sync.RWMutex
}

func NewManager(redisCli *redis.Client, cidrecord *leveldb.DB, buf *buffer.FileBuffer, nodeAddr string) *Manager {

	mg := &Manager{
		redisCli:     redisCli,
		cidRecord:    cidrecord,
		rtasks:       make(map[string]chan string),
		callbackCh:   make(chan string, task.CALLBACK_CHANNEL_SIZE),
		nodeAddr:     nodeAddr,
		databuf:      buf,
		retrieveNum:  &atomic.Uint64{},
		retrievedNum: &atomic.Uint64{},
		rw:           &sync.RWMutex{},
	}
	return mg
}

func (mg *Manager) GetNodeAddress() string {
	return mg.nodeAddr
}

func (mg *Manager) NodeStatus() Status {

	return Status{
		Address:      mg.nodeAddr,
		NTBR:         uint64(len(mg.rtasks)),
		RetrieveNum:  mg.retrieveNum.Load(),
		RetrievedNum: mg.retrievedNum.Load(),
	}
}
