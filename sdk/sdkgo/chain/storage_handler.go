package chain

import (
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

func (c *Client) QueryUnitPrice(block uint32) (*big.Int, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "UnitPrice")
	if err != nil {
		return nil, errors.Wrap(err, "query unit price error")
	}
	return data.Int, nil
}

func (c *Client) QueryTotalIdleSpace(block uint32) (uint64, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "TotalIdleSpace")
	if err != nil {
		return 0, errors.Wrap(err, "query total idle space error")
	}
	return data.Uint64(), nil
}

func (c *Client) QueryTotalServiceSpace(block uint32) (uint64, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "TotalServiceSpace")
	if err != nil {
		return 0, errors.Wrap(err, "query total service space error")
	}
	return data.Uint64(), nil
}

func (c *Client) QuerPurchasedSpace(block uint32) (uint64, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "PurchasedSpace")
	if err != nil {
		return 0, errors.Wrap(err, "query purchased space error")
	}
	return data.Uint64(), nil
}

func (c *Client) QueryTerritory(owner []byte, name string, block uint32) (TerritoryInfo, error) {
	bName, err := codec.Encode(types.NewBytes([]byte(name)))
	if err != nil {
		return TerritoryInfo{}, errors.Wrap(err, "query territory error")
	}
	data, err := QueryStorage[TerritoryInfo](c, block, "StorageHandler", "Territory", owner, bName)
	if err != nil {
		return TerritoryInfo{}, errors.Wrap(err, "query territory error")
	}
	return data, nil
}

func (c *Client) MintTerritory(name string, gibCount, days uint32, caller *signature.KeyringPair, event any) (string, error) {
	if name == "" || gibCount == 0 || days == 0 {
		return "", errors.Wrap(errors.New("bad args"), "mint territory error")
	}
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "mint territory error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(
		c.Metadata, "StorageHandler.mint_territory",
		types.NewU32(gibCount), types.NewBytes([]byte(name)), types.NewU32(days),
	)
	if err != nil {
		return "", errors.Wrap(err, "mint territory error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.mint_territory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "mint territory error")
	}

	return blockhash, nil
}

func (c *Client) ExpandingTerritory(name string, gibCount uint32, caller *signature.KeyringPair, event any) (string, error) {
	if name == "" || gibCount == 0 {
		return "", errors.Wrap(errors.New("bad args"), "expanding territory error")
	}
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "expanding territory error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(
		c.Metadata, "StorageHandler.expanding_territory",
		types.NewBytes([]byte(name)), types.NewU32(gibCount),
	)
	if err != nil {
		return "", errors.Wrap(err, "expanding territory error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.expanding_territory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "expanding territory error")
	}

	return blockhash, nil
}

func (c *Client) RenewalTerritory(name string, days uint32, caller *signature.KeyringPair, event any) (string, error) {
	if name == "" || days == 0 {
		return "", errors.Wrap(errors.New("bad args"), "renewal territory error")
	}
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "renewal territory error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(
		c.Metadata, "StorageHandler.renewal_territory",
		types.NewBytes([]byte(name)), types.NewU32(days),
	)
	if err != nil {
		return "", errors.Wrap(err, "renewal territory error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.renewal_territory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "renewal territory error")
	}

	return blockhash, nil
}

func (c *Client) ReactivateTerritory(name string, days uint32, caller *signature.KeyringPair, event any) (string, error) {
	if name == "" || days == 0 {
		return "", errors.Wrap(errors.New("bad args"), "reactivate territory error")
	}
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "reactivate territory error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(
		c.Metadata, "StorageHandler.reactivate_territory",
		types.NewBytes([]byte(name)), types.NewU32(days),
	)
	if err != nil {
		return "", errors.Wrap(err, "renewal territory error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.reactivate_territory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "reactivate territory error")
	}

	return blockhash, nil
}
