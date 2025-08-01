package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

func (c *Client) QueryCurrencyReward(block uint32) (types.U128, error) {

	data, err := QueryStorage[types.U128](c, block, "CessTreasury", "CurrencyReward")
	if err != nil {
		return data, errors.Wrap(err, "query currency reward error")
	}
	return data, nil
}

func (c *Client) QueryEraReward(block uint32) (types.U128, error) {
	data, err := QueryStorage[types.U128](c, block, "CessTreasury", "EraReward")
	if err != nil {
		return data, errors.Wrap(err, "query era reward error")
	}
	return data, nil
}

func (c *Client) QueryReserveReward(block uint32) (types.U128, error) {
	data, err := QueryStorage[types.U128](c, block, "CessTreasury", "ReserveReward")
	if err != nil {
		return data, errors.Wrap(err, "query reserve reward error")
	}
	return data, nil
}

func (c *Client) QueryRoundReward(era, block uint32) (RoundRewardType, error) {
	param, err := codec.Encode(era)
	if err != nil {
		return RoundRewardType{}, errors.Wrap(err, "query round reward error")
	}
	data, err := QueryStorage[RoundRewardType](c, block, "CessTreasury", "RoundReward", param)
	if err != nil {
		return data, errors.Wrap(err, "query round reward error")
	}
	return data, nil
}
