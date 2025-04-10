package chain

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func (c *Client) QueryOss(account []byte, block uint32) (OssInfo, error) {
	data, err := QueryStorage[OssInfo](c, block, "Oss", "Oss", account)
	if err != nil {
		return data, errors.Wrap(err, "query oss info error")
	}
	return data, nil
}

func (c *Client) QueryAllOss(block uint32) ([]OssInfo, error) {
	data, err := QueryStorages[OssInfo](c, block, "Oss", "Oss")
	if err != nil {
		return data, errors.Wrap(err, "query all oss info error")
	}
	return data, nil
}

func (c *Client) QueryAuthList(account []byte, block uint32) ([]types.AccountID, error) {
	data, err := QueryStorage[[]types.AccountID](c, block, "Oss", "AuthorityList", account)
	if err != nil {
		return data, errors.Wrap(err, "query authority list error")
	}
	return data, nil
}

func (c *Client) Authorize(account []byte, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "authorize oss error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	acc, err := types.NewAccountID(account)
	if err != nil {
		return "", errors.Wrap(err, "authorize oss error")
	}

	newcall, err := types.NewCall(c.Metadata, "Oss.authorize", *acc)
	if err != nil {
		return "", errors.Wrap(err, "authorize oss error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, " Oss.Authorize", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "authorize oss error")
	}
	return blockhash, nil
}

func (c *Client) CancelOssAuth(account []byte, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "cancel oss authorization error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(c.Metadata, "Oss.cancel_authorize", account)
	if err != nil {
		return "", errors.Wrap(err, "cancel oss authorization error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "Oss.CancelAuthorize", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "cancel oss authorization error")
	}
	return blockhash, nil
}

func (c *Client) RegisterOss(domain string, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "register oss error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	if domain == "" || len(domain) > 100 {
		return "", errors.Wrap(errors.New("bad domain"), "register oss error")
	}
	newcall, err := types.NewCall(c.Metadata, "Oss.register", [38]types.U8{}, types.NewBytes([]byte(domain)))
	if err != nil {
		return "", errors.Wrap(err, "register oss error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "Oss.OssRegister", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "register oss error")
	}
	return blockhash, nil
}

func (c *Client) UpdateOss(domain string, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "update oss error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	if domain == "" || len(domain) > 100 {
		return "", errors.Wrap(errors.New("bad domain"), "update oss error")
	}
	newcall, err := types.NewCall(c.Metadata, "Oss.update", [38]types.U8{}, types.NewBytes([]byte(domain)))
	if err != nil {
		return "", errors.Wrap(err, "update oss error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "Oss.OssUpdate", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "update oss error")
	}
	return blockhash, nil
}

func (c *Client) DestroyOss(caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "destroy oss error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(c.Metadata, "Oss.destroy")
	if err != nil {
		return "", errors.Wrap(err, "destroy oss error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "Oss.OssDestroy", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "destroy oss error")
	}
	return blockhash, nil
}
