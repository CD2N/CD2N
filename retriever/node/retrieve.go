package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/libs/task"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/CD2N/CD2N/sdk/sdkgo/logger"
	"github.com/ipfs/go-cid"
	"github.com/pkg/errors"
)

func (mg *Manager) GetDataCid(dataId string) (string, error) {
	c, err := cid.Decode(dataId)
	if err == nil {
		return c.String(), nil
	}
	var CID string
	err = client.GetData(mg.cidRecord, dataId, &CID)
	if err != nil {
		return "", errors.Wrap(err, "get data cid error")
	}
	return CID, nil
}

// func (mg *Manager) RetrieveLocalData(ctx context.Context, cid string) (string, error) {
// 	fpath, err := mg.databuf.NewBufPath(cid)
// 	if err != nil {
// 		return fpath, errors.Wrap(err, "receive local data error")
// 	}
// 	err = client.GetFileInIpfs(mg.ipfsCli, ctx, cid, fpath)
// 	if err != nil {
// 		return fpath, errors.Wrap(err, "receive local data error")
// 	}
// 	mg.databuf.AddData(cid, fpath)
// 	mg.cacher.Get(cid)
// 	return fpath, nil
// }

// func (mg *Manager) QueryLocalData(ctx context.Context, cid string) (bool, error) {
// 	ok, err := client.QueryFileInIpfs(mg.ipfsCli, ctx, cid)
// 	return ok, errors.Wrap(err, "receive local data error")
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

// func (mg *Manager) SaveAndPinedData(ctx context.Context, did, fpath string) (string, error) {
// 	cid, err := client.AddFileToIpfs(mg.ipfsCli, ctx, fpath)
// 	if err != nil {
// 		return cid, errors.Wrap(err, "save and pined data to ipfs error")
// 	}
// 	err = client.PutData(mg.cidRecord, did, cid)
// 	if err != nil {
// 		return cid, errors.Wrap(err, "save and pined data to ipfs error")
// 	}
// 	err = client.PinFileInIpfs(mg.ipfsCli, ctx, cid)
// 	if err != nil {
// 		return cid, errors.Wrap(err, "save and pined data to ipfs error")
// 	}
// 	finfo, err := os.Stat(fpath)
// 	if err == nil {
// 		mg.cacher.Add(cid, finfo.Size())
// 	}
// 	return cid, nil
// }

func (mg *Manager) CalcDataCid(did, fpath string) (string, error) {
	cid, err := client.ComputeCid(fpath, client.CID_V0)
	if err != nil {
		return cid, errors.Wrap(err, "calc data cid error")
	}
	err = client.PutData(mg.cidRecord, did, cid)
	if err != nil {
		return cid, errors.Wrap(err, "calc data cid error")
	}
	return cid, nil
}

func (mg *Manager) RetrieveData(ctx context.Context, did, requester, reqId, extdata string, exp time.Duration, sign []byte) (string, error) {
	//publish retrieve data task
	ch, err := mg.NewRetrieveDataTask(ctx, did, requester, reqId, extdata, exp, sign)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data error")
	}
	logger.GetLogger(config.LOG_RETRIEVE).Info("new retrieve data task for fragment ", did)
	timer := time.NewTimer(exp)
	select {
	case <-timer.C:
		return "", errors.Wrap(errors.New("timeout"), "retrieve data error")
	case tid := <-ch:
		return tid, nil
	}
}

func (mg *Manager) ReceiveData(ctx context.Context, tid, provider, fpath string, pubkey []byte) error {
	ok, err := client.SetNxMessage(mg.redisCli, ctx, tid+"-dlock", []byte{}, time.Second)
	if err != nil {
		return errors.Wrap(err, "receive data error")
	}
	if !ok {
		return errors.Wrap(errors.New("task data is occupied"), "receive data error")
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

	logger.GetLogger(config.LOG_RETRIEVE).Infof("receive data %s ,task id: %s", task.Did, tid)
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

func (mg *Manager) RetrieveDataService(ctx context.Context, teeUrl, user, reqId, extdata string, exp time.Duration, did string, sign []byte) (string, error) {
	cid, err := mg.GetDataCid(did)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data service error")
	}
	tid, err := mg.RetrieveData(ctx, did, user, reqId, extdata, exp, sign)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data service error")
	}
	task, err := mg.GetRetrieveTask(ctx, tid)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data service error")
	}
	rpath, err := mg.databuf.NewBufPath(cid)
	if err != nil {
		return "", errors.Wrap(err, "retrieve data service error")
	}
	if task.Pubkey != nil {
		tidBytes, _ := hex.DecodeString(tid)
		if err = client.AuditData(teeUrl, task.DataPath, rpath, client.TeeReq{
			Cid:         cid,
			UserAcc:     utils.Remove0x(user),
			Key:         task.Pubkey,
			Nonce:       tidBytes,
			RequestId:   reqId,
			UserSign:    sign,
			SupplierAcc: task.Provider,
		}); err != nil {
			return "", errors.Wrap(err, "retrieve data service error")
		}
	} else {
		rpath = task.DataPath
	}
	mg.databuf.AddData(filepath.Base(rpath), rpath)
	return rpath, nil
}
