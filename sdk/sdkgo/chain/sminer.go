package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

// QueryMinerItems retrieves the storage miner information for a specific miner account at a given block number.
// Parameters:
//
//	miner - The miner account ID (byte slice) to query information for
//	block - The block number (uint32) at which to perform the query
//
// Returns:
//
//	MinerInfo - Struct containing the queried storage miner information
//	error     - Error if the query operation fails
func (c *Client) QueryMinerItems(miner []byte, block uint32) (MinerInfo, error) {
	data, err := QueryStorage[MinerInfo](c, block, "Sminer", "MinerItems", miner)
	if err != nil {
		return data, errors.Wrap(err, "query miner items error")
	}
	return data, nil
}

// QueryAllMiners retrieves the list of all registered storage miner account IDs at a given block number.
// Parameters:
//
//	block - The block number (uint32) at which to perform the query
//
// Returns:
//
//	[]types.AccountID - Slice containing all storage miner account IDs
//	error             - Error if the query operation fails
func (c *Client) QueryAllMiners(block uint32) ([]types.AccountID, error) {
	data, err := QueryStorage[[]types.AccountID](c, block, "Sminer", "AllMiner")
	if err != nil {
		return data, errors.Wrap(err, "query all miners error")
	}
	return data, nil
}

// QueryCounterForMinerItems retrieves the counter value for storage miner items at a given block number.
// Parameters:
//
//	block - The block number (uint32) at which to perform the query
//
// Returns:
//
//	uint32 - Counter value representing the number of storage miner items
//	error  - Error if the query operation fails
func (c *Client) QueryCounterForMinerItems(block uint32) (uint32, error) {
	data, err := QueryStorage[types.U32](c, block, "Sminer", "CounterForMinerItems")
	if err != nil {
		return 0, errors.Wrap(err, "query all miners error")
	}
	return uint32(data), nil
}
