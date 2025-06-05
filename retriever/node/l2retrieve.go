package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/tsproto"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/pkg/errors"
)

type L2Retriever interface {
	GetRetrieveTask(ctx context.Context, tid string) (task.RetrieveTask, error)
	ReceiveData(ctx context.Context, tid, provider, fpath string, pubkey []byte) error
	RetrieveDataFromL2(ctx context.Context, reqId, extdata, user string, exp time.Duration, did string, sign []byte) (string, error)
}

// func (mg *Manager) GetDataCid(dataId string) (string, error) {
// 	c, err := cid.Decode(dataId)
// 	if err == nil {
// 		return c.String(), nil
// 	}
// 	var CID string
// 	err = client.GetData(mg.cidRecord, dataId, &CID)
// 	if err != nil {
// 		return "", errors.Wrap(err, "get data cid error")
// 	}
// 	return CID, nil
// }

func (mg *Manager) GetRetrieveTask(ctx context.Context, tid string) (task.RetrieveTask, error) {
	var rtask task.RetrieveTask
	data := client.GetMessage(mg.redisCli, ctx, tid)
	if len(data) == 0 {
		return rtask, errors.Wrap(errors.New("empty data"), "get retrieve task error")
	}
	err := json.Unmarshal(data, &rtask)
	if err != nil {
		return rtask, errors.Wrap(err, "get retrieve task error")
	}
	return rtask, nil
}

func (mg *Manager) RetrieveData(ctx context.Context, did, requester, reqId, extdata string, exp time.Duration, sign []byte) (string, error) {
	//publish retrieve data task
	mg.retrieveNum.Add(1)
	ch, err := mg.NewRetrieveDataTask(ctx, did, requester, reqId, extdata, exp, sign)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data error")
	}
	timer := time.NewTimer(exp)
	select {
	case <-ctx.Done():
		return "", errors.Wrap(ctx.Err(), "retrieve data error")
	case <-timer.C:
		return "", errors.Wrap(errors.New("task timeout"), "retrieve data error")
	case tid := <-ch:
		mg.retrievedNum.Add(1)
		return tid, nil
	}
}

func (mg *Manager) ReceiveData(ctx context.Context, tid, provider, fpath string, pubkey []byte) error {
	ok, err := client.SetNxMessage(mg.redisCli, ctx, tid+"-dlock", []byte{}, time.Millisecond*200)
	if err != nil {
		return errors.Wrap(err, "receive data error")
	}
	if !ok {
		return errors.Wrap(fmt.Errorf("task %s is occupied", tid), "receive data error")
	}
	task, err := mg.GetRetrieveTask(ctx, tid)
	if err != nil {
		return errors.Wrap(err, "receive data error")
	}
	task.Provider = provider
	task.Pubkey = pubkey
	task.DataPath = fpath
	task.RespTime = time.Now().Format(config.TIME_LAYOUT)
	err = client.SetMessage(mg.redisCli, ctx, tid, task.Marshal(), time.Duration(task.Exp))
	if err != nil {
		return errors.Wrap(err, "receive data error")
	}

	logger.GetLogger(config.LOG_RETRIEVE).Infof("receive data %s, from file %s ,task id: %s", task.Did, task.ExtData, tid)
	mg.callbackCh <- tid
	return nil
}

func (mg *Manager) NewRetrieveDataTask(ctx context.Context, did, requester, reqId, extdata string, exp time.Duration, sign []byte) (chan string, error) {
	ch := make(chan string, 1)
	task := NewRetrieveTask(did, requester, mg.nodeAddr, reqId, extdata, int64(exp), sign)
	err := client.SetMessage(mg.redisCli, ctx, task.Tid, task.Marshal(), exp)
	if err != nil {
		return nil, errors.Wrap(err, "new retrieve data task error")
	}
	err = client.PublishMessage(mg.redisCli, ctx, client.CHANNEL_RETRIEVE, task.Task)
	if err != nil {
		return nil, errors.Wrap(err, "new retrieve data task error")
	}
	logger.GetLogger(config.LOG_RETRIEVE).Infof("new retrieve data task %s for fragment %s, from file %s", task.Tid, did, extdata)
	mg.rw.Lock()
	defer mg.rw.Unlock()
	mg.rtasks[task.Tid] = ch
	return ch, nil
}

func (mg *Manager) CallbackManager(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case tid := <-mg.callbackCh:
			mg.rw.RLock()
			signal := mg.rtasks[tid]
			delete(mg.rtasks, tid)
			signal <- tid
			close(signal)
			mg.rw.RUnlock()
		}
	}
}

func NewRetrieveTask(did, reqer, acc, reqId, extdata string, exp int64, sign []byte) task.RetrieveTask {
	rand, _ := utils.GetRandomBytes()
	conf := config.GetConfig()
	return task.RetrieveTask{
		Task: task.Task{
			Tid:       hex.EncodeToString(rand[:task.TID_BYTES_LEN]),
			Exp:       exp,
			Acc:       acc,
			Addr:      conf.Endpoint,
			Did:       did,
			ExtData:   extdata,
			Timestamp: time.Now().Format(config.TIME_LAYOUT),
		},
		Requester: reqer,
		RequestId: reqId,
		Sign:      sign,
	}
}

//u, err := url.JoinPath(h.teeEndpoint, client.AUDIT_DATA_URL)

func (mg *Manager) RetrieveDataFromL2(ctx context.Context, reqId, extdata, user string, exp time.Duration, did string, sign []byte) (string, error) {

	u, err := url.JoinPath(mg.teeEndpoint, tsproto.AUDIT_DATA_URL)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}

	tid, err := mg.RetrieveData(ctx, did, mg.nodeAddr, reqId, extdata, exp, sign)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}
	task, err := mg.GetRetrieveTask(ctx, tid)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}
	rpath, err := mg.databuf.NewBufPath(tid)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data from l2 cache network error")
	}
	if user == "" {
		user = utils.Remove0x(mg.nodeAddr)
	} else {
		user = utils.Remove0x(user)
	}
	if len(task.Pubkey) > 0 {
		tidBytes, _ := hex.DecodeString(tid)
		if err = tsproto.AuditData(u, task.DataPath, rpath, tsproto.TeeReq{
			Cid:         did,
			UserAcc:     user,
			Key:         task.Pubkey,
			Nonce:       tidBytes,
			RequestId:   reqId,
			UserSign:    sign,
			SupplierAcc: task.Provider,
		}); err != nil {
			return "", errors.Wrap(err, "retrieve data from l2 cache network error")
		}
	} else {
		rpath = task.DataPath
	}
	mg.databuf.AddData(filepath.Base(rpath), rpath)
	return rpath, nil
}
