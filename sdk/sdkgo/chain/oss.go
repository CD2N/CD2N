package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

// QueryOss retrieves the OSS information for a specific account at a given block number.
// Parameters:
//
//	account - The account ID (byte slice) to query OSS information for
//	block   - The block number (uint32) at which to perform the query
//
// Returns:
//
//	OssInfo - Struct containing the queried OSS information
//	error   - Error if the query operation fails
func (c *Client) QueryOss(account []byte, block uint32) (OssInfo, error) {
	data, err := QueryStorage[OssInfo](c, block, "Oss", "Oss", account)
	if err != nil {
		return data, errors.Wrap(err, "query oss info error")
	}
	return data, nil
}

// QueryAllOss retrieves OSS information for all registered accounts at a given block number.
// Parameters:
//
//	block - The block number (uint32) at which to perform the query
//
// Returns:
//
//	[]OssInfo - Slice containing OSS information for all accounts
//	error      - Error if the query operation fails
func (c *Client) QueryAllOss(block uint32) ([]OssInfo, error) {
	data, err := QueryStorages[OssInfo](c, block, "Oss", "Oss")
	if err != nil {
		return data, errors.Wrap(err, "query all oss info error")
	}
	return data, nil
}

// QueryAuthList retrieves the authorization list for a specific account at a given block number.
// Parameters:
//
//	account - The account ID (byte slice) to query authorization list for
//	block   - The block number (uint32) at which to perform the query
//
// Returns:
//
//	[]types.AccountID - Slice of authorized account IDs
//	error             - Error if the query operation fails
func (c *Client) QueryAuthList(account []byte, block uint32) ([]types.AccountID, error) {
	data, err := QueryStorage[[]types.AccountID](c, block, "Oss", "AuthorityList", account)
	if err != nil {
		return data, errors.Wrap(err, "query authority list error")
	}
	return data, nil
}

// Authorize grants authorization to a target account for OSS operations.
// Parameters:
//
//	account - The target account ID (byte slice) to authorize
//	caller  - Keyring pair of the account initiating the authorization (nil for temporary key)
//	event   - Event pointer, used to receive specified events
//
// Returns:
//
//	string  - Block hash of the submitted transaction
//	error   - Error if the authorization operation fails
func (c *Client) Authorize(account []byte, caller *signature.KeyringPair, event any) (string, error) {

	acc, err := types.NewAccountID(account)
	if err != nil {
		return "", errors.Wrap(err, "authorize oss error")
	}

	newcall, err := types.NewCall(c.Metadata, "Oss.authorize", *acc)
	if err != nil {
		return "", errors.Wrap(err, "authorize oss error")
	}

	blockhash, err := c.SubmitExtrinsic(caller, newcall, " Oss.Authorize", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "authorize oss error")
	}
	return blockhash, nil
}

// CancelOssAuth revokes authorization from a target account for OSS operations.
// Parameters:
//
//	account - The target account ID (byte slice) to revoke authorization from
//	caller  - Keyring pair of the account initiating the cancellation (nil for temporary key)
//	event   - Event pointer, used to receive specified events
//
// Returns:
//
//	string  - Block hash of the submitted transaction
//	error   - Error if the cancellation operation fails
func (c *Client) CancelOssAuth(account []byte, caller *signature.KeyringPair, event any) (string, error) {

	newcall, err := types.NewCall(c.Metadata, "Oss.cancel_authorize", account)
	if err != nil {
		return "", errors.Wrap(err, "cancel oss authorization error")
	}

	blockhash, err := c.SubmitExtrinsic(caller, newcall, "Oss.CancelAuthorize", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "cancel oss authorization error")
	}
	return blockhash, nil
}

// RegisterOss registers a new OSS service with the specified domain name.
// Parameters:
//
//	domain  - The domain name (string) for the OSS service (must be 1-100 characters)
//	caller  - Keyring pair of the account initiating the registration (nil for temporary key)
//	event   - Event pointer, used to receive specified events
//
// Returns:
//
//	string  - Block hash of the submitted transaction
//	error   - Error if the registration operation fails
func (c *Client) RegisterOss(domain string, caller *signature.KeyringPair, event any) (string, error) {

	if domain == "" || len(domain) > 100 {
		return "", errors.Wrap(errors.New("bad domain"), "register oss error")
	}
	newcall, err := types.NewCall(c.Metadata, "Oss.register", [38]types.U8{}, types.NewBytes([]byte(domain)))
	if err != nil {
		return "", errors.Wrap(err, "register oss error")
	}

	blockhash, err := c.SubmitExtrinsic(caller, newcall, "Oss.OssRegister", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "register oss error")
	}
	return blockhash, nil
}

// UpdateOss updates the domain name of an existing OSS service.
// Parameters:
//
//	domain  - The new domain name (string) for the OSS service (must be 1-100 characters)
//	caller  - Keyring pair of the account initiating the update (nil for temporary key)
//	event   - Event pointer, used to receive specified events
//
// Returns:
//
//	string  - Block hash of the submitted transaction
//	error   - Error if the update operation fails
func (c *Client) UpdateOss(domain string, caller *signature.KeyringPair, event any) (string, error) {

	if domain == "" || len(domain) > 100 {
		return "", errors.Wrap(errors.New("bad domain"), "update oss error")
	}
	newcall, err := types.NewCall(c.Metadata, "Oss.update", [38]types.U8{}, types.NewBytes([]byte(domain)))
	if err != nil {
		return "", errors.Wrap(err, "update oss error")
	}

	blockhash, err := c.SubmitExtrinsic(caller, newcall, "Oss.OssUpdate", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "update oss error")
	}
	return blockhash, nil
}

// DestroyOss deletes an existing OSS service registration.
// Parameters:
//
//	caller  - Keyring pair of the account initiating the destruction (nil for temporary key)
//	event   - Event pointer, used to receive specified events
//
// Returns:
//
//	string  - Block hash of the submitted transaction
//	error   - Error if the destruction operation fails
func (c *Client) DestroyOss(caller *signature.KeyringPair, event any) (string, error) {

	newcall, err := types.NewCall(c.Metadata, "Oss.destroy")
	if err != nil {
		return "", errors.Wrap(err, "destroy oss error")
	}

	blockhash, err := c.SubmitExtrinsic(caller, newcall, "Oss.OssDestroy", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "destroy oss error")
	}
	return blockhash, nil
}
