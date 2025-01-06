package chain

import (
	"context"
	"time"

	cess "github.com/CESSProject/cess-go-sdk"
	"github.com/CESSProject/cess-go-sdk/chain"
	"github.com/pkg/errors"
)

func NewCessChainClient(ctx context.Context, rpcs []string) (chain.Chainer, error) {
	var (
		chainCli chain.Chainer
		err      error
	)
	for i := 0; i < 3; i++ {
		chainCli, err = cess.New(
			ctx,
			cess.ConnectRpcAddrs(rpcs),
			cess.TransactionTimeout(30*time.Second),
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
