package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

// QueryBlockNumber retrieves the block number from the blockchain.
// If blockhash is provided, it queries the block number for the specified block hash.
// If blockhash is empty, it retrieves the latest block number.
// Parameters:
//
//	blockhash - The hexadecimal string of the block hash (empty for the latest block).
//
// Returns:
//
//	uint32 - The block number.
//	error - An error if the query fails, including decoding errors or RPC failures.
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

// QueryAccountInfo retrieves the account information for a specific account at the given block height.
// Parameters:
//
//	account - The byte slice representing the account address.
//	block - The block number at which to query the account information.
//
// Returns:
//
//	types.AccountInfo - The account information struct containing details like nonce, consumers, providers, etc.
//	error - An error if the query fails, including account ID creation errors, encoding errors, or storage query failures.
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
