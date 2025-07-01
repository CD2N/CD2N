package chain

import (
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

// TransferToken transfers tokens from the caller's account to the destination account.
// It ensures the caller's account remains alive (non-zero balance after transfer).
// Parameters:
//
//	dest - The destination account address (SS58 format string)
//	amount - The amount of tokens to transfer, ("1000000000000000000" represents 1 CESS token).
//	caller - The keyring pair of the transaction signer
//	event - A pointer to an event structure that will be populated if the transaction is successful
//
// Returns:
//
//	Block hash of the transaction
//	Error if the transfer fails (e.g., invalid address, insufficient balance)
func (c *Client) TransferToken(dest string, amount string, caller *signature.KeyringPair, event any) (string, error) {

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

	blockhash, err := c.SubmitExtrinsic(caller, newcall, "Balances.Transfer", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "transfer token error")
	}
	return blockhash, nil
}
