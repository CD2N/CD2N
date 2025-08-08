package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func (c *Client) QueryValidators(block uint32) ([]types.AccountID, error) {
	data, err := QueryStorage[[]types.AccountID](c, block, "Session", "Validators")
	if err != nil {
		return data, errors.Wrap(err, "query validators error")
	}
	return data, nil
}
