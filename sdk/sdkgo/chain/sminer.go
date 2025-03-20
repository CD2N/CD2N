package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func (c *Client) QueryMinerItems(accountID []byte, block uint32) (MinerInfo, error) {
	data, err := QueryStorage[MinerInfo](c, block, "Sminer", "MinerItems", accountID)
	if err != nil {
		return data, errors.Wrap(err, "query miner items error")
	}
	return data, nil
}

func (c *Client) QueryAllMiners(block uint32) ([]types.AccountID, error) {
	data, err := QueryStorage[[]types.AccountID](c, block, "Sminer", "AllMiner")
	if err != nil {
		return data, errors.Wrap(err, "query all miners error")
	}
	return data, nil
}

func (c *Client) QueryCounterForMinerItems(block uint32) (uint32, error) {
	data, err := QueryStorage[types.U32](c, block, "Sminer", "CounterForMinerItems")
	if err != nil {
		return 0, errors.Wrap(err, "query all miners error")
	}
	return uint32(data), nil
}
