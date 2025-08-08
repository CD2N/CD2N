package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

func (c *Client) QueryCounterForValidators(block uint32) (uint32, error) {
	data, err := QueryStorage[types.U32](c, block, "Staking", "CounterForValidators")
	if err != nil {
		return uint32(data), errors.Wrap(err, "query counter for validators error")
	}
	return uint32(data), nil
}

func (c *Client) QueryErasTotalStaking(era, block uint32) (types.U128, error) {
	param, err := codec.Encode(era)
	if err != nil {
		return types.U128{}, errors.Wrap(err, "query eras total staking error")
	}
	data, err := QueryStorage[types.U128](c, block, "Staking", "ErasTotalStake", param)
	if err != nil {
		return data, errors.Wrap(err, "query eras total staking error")
	}
	return data, nil
}

func (c *Client) QueryCurrentEra(block uint32) (uint32, error) {
	data, err := QueryStorage[types.U32](c, block, "Staking", "CurrentEra")
	if err != nil {
		return uint32(data), errors.Wrap(err, "query current era error")
	}
	return uint32(data), nil
}

func (c *Client) QueryErasRewardPoints(era, block uint32) (StakingEraRewardPoints, error) {
	param, err := codec.Encode(era)
	if err != nil {
		return StakingEraRewardPoints{}, errors.Wrap(err, "query eras reward points error")
	}
	data, err := QueryStorage[StakingEraRewardPoints](c, block, "Staking", "ErasRewardPoints", param)
	if err != nil {
		return data, errors.Wrap(err, "query eras reward points error")
	}
	return data, nil
}

func (c *Client) QueryAllNominators(block uint32) ([]StakingNominations, error) {
	data, err := QueryStorages[StakingNominations](c, block, "Staking", "Nominators")
	if err != nil {
		return data, errors.Wrap(err, "query all nominators error")
	}
	return data, nil
}

func (c *Client) QueryAllBondeds(block uint32) ([]types.AccountID, error) {
	data, err := QueryStorages[types.AccountID](c, block, "Staking", "Bonded")
	if err != nil {
		return data, errors.Wrap(err, "query all bondeds error")
	}
	return data, nil
}

func (c *Client) QueryValidatorCommission(accountId []byte, block uint32) (StakingValidatorPrefs, error) {
	data, err := QueryStorage[StakingValidatorPrefs](c, block, "Staking", "Validators", accountId)
	if err != nil {
		return data, errors.Wrap(err, "query validator commission error")
	}
	return data, nil
}

func (c *Client) QueryEraValidatorReward(era, block uint32) (types.U128, error) {
	param, err := codec.Encode(era)
	if err != nil {
		return types.U128{}, errors.Wrap(err, "query eras validator reward error")
	}
	data, err := QueryStorage[types.U128](c, block, "Staking", "ErasValidatorReward", param)
	if err != nil {
		return data, errors.Wrap(err, "query eras validator reward error")
	}
	return data, nil
}

func (c *Client) QueryLedger(accountId []byte, block uint32) (StakingLedger, error) {
	data, err := QueryStorage[StakingLedger](c, block, "Staking", "Ledger", accountId)
	if err != nil {
		return data, errors.Wrap(err, "query ledger error")
	}
	return data, nil
}

func (c *Client) QueryErasStakers(accountId []byte, era, block uint32) (StakingExposure, error) {

	param, err := codec.Encode(era)
	if err != nil {
		return StakingExposure{}, errors.Wrap(err, "query eras stakers error")
	}
	data, err := QueryStorage[StakingExposure](c, block, "Staking", "ErasStakers", param, accountId)
	if err != nil {
		return data, errors.Wrap(err, "query eras stakers error")
	}
	return data, nil
}

func (c *Client) QueryNominators(accountId []byte, block uint32) (StakingNominations, error) {
	data, err := QueryStorage[StakingNominations](c, block, "Staking", "Nominators", accountId)
	if err != nil {
		return data, errors.Wrap(err, "query nominators error")
	}
	return data, nil
}

func (c *Client) QueryAllErasStakersPaged(accountId []byte, era, block uint32) ([]StakingExposurePaged, error) {
	param, err := codec.Encode(era)
	if err != nil {
		return nil, errors.Wrap(err, "query all eras stakers paged error")
	}

	data := make([]StakingExposurePaged, 0, 256)

	for i := range 256 {
		paramI, err := codec.Encode(types.U32(i))
		if err != nil {
			return nil, errors.Wrap(err, "query all eras stakers paged error")
		}
		d, err := QueryStorage[StakingExposurePaged](c, block, "Staking", "ErasStakersPaged", param, accountId, paramI)
		if err != nil {
			return nil, errors.Wrap(err, "query all eras stakers paged error")
		}
		data = append(data, d)
	}
	return data, nil
}

func (c *Client) QueryErasStakersOveriew(accountId []byte, era, block uint32) (PagedExposureMetadata, error) {

	param, err := codec.Encode(era)
	if err != nil {
		return PagedExposureMetadata{}, errors.Wrap(err, "query eras stakers overiew error")
	}
	data, err := QueryStorage[PagedExposureMetadata](c, block, "Staking", "ErasStakers", param, accountId)
	if err != nil {
		return data, errors.Wrap(err, "query eras stakers error")
	}
	return data, nil
}
