package chain

import (
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func (c *Client) TransferToken(dest string, amount string, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "exec territory order error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	pubkey, err := ParsingPublickey(dest)
	if err != nil {
		return "", errors.Wrap(err, "transfer token error")
	}

	address, err := types.NewMultiAddressFromAccountID(pubkey)
	if err != nil {
		return "", errors.Wrap(err, "transfer token error")
	}

	amount_bg, ok := new(big.Int).SetString(amount, 10)
	if !ok {
		return "", errors.Wrap(errors.New("bad amount"), "transfer token error")
	}

	newcall, err := types.NewCall(c.Metadata, "Balances.transfer_keep_alive", address, types.NewUCompact(amount_bg))
	if err != nil {
		return "", errors.Wrap(err, "transfer token error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "Balances.Transfer", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "transfer token error")
	}
	return blockhash, nil
}
