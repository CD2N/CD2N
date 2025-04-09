package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

func (c *Client) QueryBlockNumber(blockhash string) (uint32, error) {
	var (
		block *types.SignedBlock
		h     types.Hash
		err   error
	)
	if blockhash != "" {
		err = codec.DecodeFromHex(blockhash, &h)
		if err != nil {
			return 0, errors.Wrap(err, "query block number error")
		}
		block, err = c.RPC.Chain.GetBlock(h)
	} else {
		block, err = c.RPC.Chain.GetBlockLatest()
	}
	if err != nil {
		return 0, errors.Wrap(err, "query block number error")
	}
	return uint32(block.Block.Header.Number), nil
}

func (c *Client) QueryAccountInfo(account []byte, block uint32) (types.AccountInfo, error) {
	acc, err := types.NewAccountID(account)
	if err != nil {
		return types.AccountInfo{}, errors.Wrap(err, "query account info error")
	}

	b, err := codec.Encode(*acc)
	if err != nil {
		return types.AccountInfo{}, errors.Wrap(err, "query account info error")
	}
	data, err := QueryStorage[types.AccountInfo](c, block, "System", "Account", b)
	if err != nil {
		return data, errors.Wrap(err, "query account info error")
	}
	return data, nil
}
