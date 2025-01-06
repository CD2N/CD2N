package chain

import (
	"context"
	"time"

	cess "github.com/CESSProject/cess-go-sdk"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/pkg/errors"
)

// type StorageOrderReq struct {
// 	Fid       string
// 	Name      string
// 	Territory string
// 	Segment   []chain.SegmentDataInfo
// 	Owner     []byte
// 	Size      uint64
// }

func NewCessChainClient(ctx context.Context, mnemonic string, rpcs []string) (chain.Chainer, error) {
	var (
		chainCli chain.Chainer
		err      error
	)
	time.Sleep(time.Second * 15)
	for i := 0; i < 3; i++ {
		chainCli, err = cess.New(
			ctx,
			cess.ConnectRpcAddrs(rpcs),
			cess.TransactionTimeout(30*time.Second),
			cess.Mnemonic(mnemonic),
		)
		if err == nil {
			break
		}
	}
	if err != nil || chainCli == nil {
		return nil, errors.Wrap(err, "new cess chain client error")
	}
	if err = chainCli.InitExtrinsicsNameForOSS(); err != nil {
		return nil, errors.Wrap(err, "new cess chain client error")
	}
	return chainCli, nil
}

func QueryDealMap(cli chain.Chainer, fid string) (map[int]struct{}, error) {
	cmpSet := make(map[int]struct{})
	order, err := cli.QueryDealMap(fid, -1)
	if err != nil {
		return cmpSet, errors.Wrap(err, "query file deal map on chain error")
	}
	for _, c := range order.CompleteList {
		cmpSet[int(c.Index)] = struct{}{}
	}
	return cmpSet, nil
}

func CreateStorageOrder(cli chain.Chainer, fid, name, territory string, segments []chain.SegmentDataInfo, owner []byte, size uint64) (string, error) {
	hash, err := cli.PlaceStorageOrder(fid, name, territory, segments, owner, size)
	if err != nil {
		return "", errors.Wrap(err, "place storage order error")
	}
	return hash, nil
}
