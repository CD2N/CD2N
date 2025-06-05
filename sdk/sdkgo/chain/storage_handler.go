package chain

import (
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

// QueryUnitPrice retrieves the unit price for storage handling from the blockchain at the specified block height.
// Parameters:
//
//	block - The block number at which to query the storage.
//
// Returns:
//
//	*big.Int - The unit price value.
//	error - An error if the query fails, including wrapped errors from underlying storage queries.
func (c *Client) QueryUnitPrice(block uint32) (*big.Int, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "UnitPrice")
	if err != nil {
		return nil, errors.Wrap(err, "query unit price error")
	}
	return data.Int, nil
}

// QueryTotalIdleSpace retrieves the total idle storage space from the blockchain at the specified block height.
// Parameters:
//
//	block - The block number at which to query the storage.
//
// Returns:
//
//	uint64 - The total idle space value.
//	error - An error if the query fails, including wrapped errors from underlying storage queries.
func (c *Client) QueryTotalIdleSpace(block uint32) (uint64, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "TotalIdleSpace")
	if err != nil {
		return 0, errors.Wrap(err, "query total idle space error")
	}
	return data.Uint64(), nil
}

// QueryTotalServiceSpace retrieves the total In-service storage space from the blockchain at the specified block height.
// Parameters:
//
//	block - The block number at which to query the storage.
//
// Returns:
//
//	uint64 - The total serviceable space value.
//	error - An error if the query fails, including wrapped errors from underlying storage queries.
func (c *Client) QueryTotalServiceSpace(block uint32) (uint64, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "TotalServiceSpace")
	if err != nil {
		return 0, errors.Wrap(err, "query total service space error")
	}
	return data.Uint64(), nil
}

// QuerPurchasedSpace retrieves the total purchased storage space from the blockchain at the specified block height.
// Parameters:
//
//	block - The block number at which to query the storage.
//
// Returns:
//
//	uint64 - The total purchased space value.
//	error - An error if the query fails, including wrapped errors from underlying storage queries.
func (c *Client) QuerPurchasedSpace(block uint32) (uint64, error) {
	data, err := QueryStorage[types.U128](c, block, "StorageHandler", "PurchasedSpace")
	if err != nil {
		return 0, errors.Wrap(err, "query purchased space error")
	}
	return data.Uint64(), nil
}

// QueryTerritory retrieves detailed information about a specific territory from the blockchain at the specified block height.
// Parameters:
//
//	owner - The owner's account address (byte slice).
//	name - The name of the territory.
//	block - The block number at which to query the storage.
//
// Returns:
//
//	TerritoryInfo - Struct containing territory details.
//	error - An error if the query fails, including encoding errors or underlying storage query failures.
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

// MintTerritory mints a new territory on the blockchain.
// Parameters:
//
//	name - The name of the territory.
//	gibCount - The initial size of the territory in GiB.
//	days - The duration of the territory in days.
//	caller - The keyring pair of the transaction signer. If nil, the client's keyring will be used.
//	event - A pointer to an event structure that will be populated if the transaction is successful.
//
// Returns:
//
//	string - The block hash of the transaction.
//	error - An error if the transaction fails, including encoding errors, key retrieval, extrinsic creation, or submission errors.
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

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.MintTerritory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "mint territory error")
	}

	return blockhash, nil
}

// ExpandingTerritory expands an existing territory on the blockchain.
// Parameters:
//
//	name - The name of the territory to expand.
//	gibCount - The additional size to add to the territory in GiB.
//	caller - The keyring pair of the transaction signer. If nil, the client's keyring will be used.
//	event - A pointer to an event structure that will be populated if the transaction is successful.
//
// Returns:
//
//	string - The block hash of the transaction.
//	error - An error if the transaction fails, including encoding errors, key retrieval, extrinsic creation, or submission errors.
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

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.ExpansionTerritory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "expanding territory error")
	}

	return blockhash, nil
}

// RenewalTerritory renews an existing territory on the blockchain.
// Parameters:
//
//	name - The name of the territory to renew.
//	days - The additional duration to add to the territory in days.
//	caller - The keyring pair of the transaction signer. If nil, the client's keyring will be used.
//	event - A pointer to an event structure that will be populated if the transaction is successful.
//
// Returns:
//
//	string - The block hash of the transaction.
//	error - An error if the transaction fails, including encoding errors, key retrieval, extrinsic creation, or submission errors.
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

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.RenewalTerritory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "renewal territory error")
	}

	return blockhash, nil
}

// ReactivateTerritory reactivates an existing territory on the blockchain.
// Parameters:
//
//	name - The name of the territory to reactivate.
//	days - The additional duration to add to the territory in days.
//	caller - The keyring pair of the transaction signer. If nil, the client's keyring will be used.
//	event - A pointer to an event structure that will be populated if the transaction is successful.
//
// Returns:
//
//	string - The block hash of the transaction.
//	error - An error if the transaction fails, including encoding errors, key retrieval, extrinsic creation, or submission errors.
//
// Note: This function is similar to RenewalTerritory but does not require a new name. It can be used to extend the activation period of an existing territory.
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

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.ReactivateTerritory", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "reactivate territory error")
	}

	return blockhash, nil
}

// CreateTerritoryOrder creates a new territory order on the blockchain.
// This method is used by the agent to create a territory for other users.
// Parameters:
//
//	account - The account ID of the owner of the territory.
//	name - The name of the territory.
//	orderType - The type of order (e.g., mint, expand, renew, reactivate).
//	gibCount - The size of the territory in GiB.
//	days - The duration of the territory in days.
//	expired - The expiration time of the order in Unix timestamp.
//	caller - The keyring pair of the transaction signer. If nil, the client's keyring will be used.
//	event - A pointer to an event structure that will be populated if the transaction is successful.
//
// Returns:
//
//	string - The block hash of the transaction.
//	error - An error if the transaction fails, including encoding errors, key retrieval, extrinsic creation, or submission errors.
func (c *Client) CreateTerritoryOrder(account []byte, name string, orderType uint8, gibCount, days, expired uint32, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "create territory order error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	addr, err := types.NewAccountID(account)
	if err != nil {
		return "", errors.Wrap(err, "create territory order error")
	}
	newcall, err := types.NewCall(
		c.Metadata, "StorageHandler.create_order", *addr,
		types.NewBytes([]byte(name)), types.NewU8(orderType),
		types.NewU32(gibCount), types.NewU32(days), types.NewU32(expired),
	)

	if err != nil {
		return "", errors.Wrap(err, "create territory order error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.CreatePayOrder", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "create territory order error")
	}

	return blockhash, nil
}

// ExecTerritoryOrder executes a territory order on the blockchain.
// This method is used by the agent to execute a territory order for other users.
// Parameters:
//
//	orderId - The ID of the order to execute.
//	caller - The keyring pair of the transaction signer. If nil, the client's keyring will be used.
//	event - A pointer to an event structure that will be populated if the transaction is successful.
//
// Returns:
//
//	string - The block hash of the transaction.
//	error - An error if the transaction fails, including encoding errors, key retrieval, extrinsic creation, or submission errors.
func (c *Client) ExecTerritoryOrder(orderId []byte, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "exec territory order error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}
	newcall, err := types.NewCall(c.Metadata, "StorageHandler.exec_order", types.NewBytes(orderId))
	if err != nil {
		return "", errors.Wrap(err, "exec territory order error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "StorageHandler.PaidOrder", event, c.Timeout)
	if err != nil {
		return "", errors.Wrap(err, "exec territory order error")
	}

	return blockhash, nil
}

// GetOssProxyAuthSign retrieves the OSS proxy authorization sign for a given mnemonic and OSS account.
// Parameters:
//
//	mnemonic - The mnemonic phrase for the key pair.
//	oss - The public key of the OSS account.
//
// Returns:
//
//	[]byte - The public key of the key pair.
//	[]byte - The signed authorization data.
//	error - An error if the sign operation fails.
func (c *Client) GetOssProxyAuthSign(mnemonic, oss string) ([]byte, []byte, error) {

	keyring, err := signature.KeyringPairFromSecret(mnemonic, 11331)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get oss porxy auth error")
	}
	ossPk, err := ParsingPublickey(oss)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get oss porxy auth error")
	}
	ossAccid, err := types.NewAccountID(ossPk)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get oss porxy auth error")
	}
	num, err := c.QueryBlockNumber("")
	if err != nil {
		return nil, nil, errors.Wrap(err, "get oss porxy auth error")
	}
	pld := SignPayload{
		Oss: *ossAccid,
		Exp: types.NewU32(num),
	}
	body, err := pld.EncodeSignPayload()
	if err != nil {
		return nil, nil, errors.Wrap(err, "get oss porxy auth error")
	}
	sign, err := SignedSR25519WithMnemonic(keyring.URI, append([]byte("<Bytes>"), append(body, []byte("</Bytes>")...)...))
	if err != nil {
		return nil, nil, errors.Wrap(err, "get oss porxy auth error")
	}
	return keyring.PublicKey, sign, nil
}
