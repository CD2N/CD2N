package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func (c *Client) SendEvmCall(
	source, target types.H160, input types.Bytes, value types.U256,
	gasLimit types.U64, maxFeePerGas types.U256, accessList []AccessInfo,
	caller *signature.KeyringPair, event any,
) (string, error) {
	var (
		nonce                types.Option[types.U256]
		maxPriorityFeePerGas types.Option[types.U256]
	)
	nonce.SetNone()
	maxPriorityFeePerGas.SetNone()
	newcall, err := types.NewCall(
		c.Metadata, "EVM.call", source, target, input, value,
		gasLimit, maxFeePerGas, maxPriorityFeePerGas, nonce, accessList,
	)
	if err != nil {
		return "", errors.Wrap(err, "send evem call error")
	}

	blockhash, err := c.SubmitExtrinsic(caller, newcall, "EVM.Call", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "send evem call error")
	}

	return blockhash, nil
}
