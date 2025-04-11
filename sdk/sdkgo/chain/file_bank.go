package chain

import (
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

func (c *Client) QueryDealMap(fid string, block uint32) (StorageOrder, error) {
	var (
		data StorageOrder
		hash FileHash
	)
	if fid == "" || len(fid) != 64 {
		return data, errors.Wrap(errors.New("bad fid"), "query deal map error")
	}
	for i := 0; i < len(fid); i++ {
		hash[i] = types.U8(fid[i])
	}
	h, err := codec.Encode(hash)
	if err != nil {
		return data, errors.Wrap(err, "query deal map error")
	}
	data, err = QueryStorage[StorageOrder](c, block, "FileBank", "DealMap", h)
	if err != nil {
		return data, errors.Wrap(err, "query deal map error")
	}
	return data, nil
}

func (c *Client) QueryFileMetadata(fid string, block uint32) (FileMetadata, error) {
	var (
		data FileMetadata
		hash FileHash
	)
	if fid == "" || len(fid) != 64 {
		return data, errors.Wrap(errors.New("bad fid"), "query deal map error")
	}
	for i := range len(fid) {
		hash[i] = types.U8(fid[i])
	}
	h, err := codec.Encode(hash)
	if err != nil {
		return data, errors.Wrap(err, "query deal map error")
	}
	data, err = QueryStorage[FileMetadata](c, block, "FileBank", "DealMap", h)
	if err != nil {
		return data, errors.Wrap(err, "query deal map error")
	}
	return data, nil
}

func (c *Client) QueryUserFileList(accountID []byte, block uint32) ([]UserFileSliceInfo, error) {
	acc, err := types.NewAccountID(accountID)
	if err != nil {
		return nil, errors.Wrap(err, "query user's file list error")
	}
	user, err := codec.Encode(*acc)
	if err != nil {
		return nil, errors.Wrap(err, "query user's file list error")
	}
	data, err := QueryStorage[[]UserFileSliceInfo](c, block, "FileBank", "UserHoldFileList", user)
	if err != nil {
		return nil, errors.Wrap(err, "query user's file list error")
	}
	return data, nil
}

func (c *Client) UploadDeclaration(fid FileHash, segment []SegmentList, user UserBrief, filesize uint64, caller *signature.KeyringPair, event any) (string, error) {

	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "upload file declaration error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(c.Metadata, "FileBank.upload_declaration", fid, segment, user, types.NewU128(*new(big.Int).SetUint64(filesize)))
	if err != nil {
		return "", errors.Wrap(err, "upload file declaration error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "FileBank.UploadDeclaration", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "upload file declaration error")
	}
	return blockhash, nil
}

func (c *Client) DeleteUserFile(fid FileHash, owner types.AccountID, caller *signature.KeyringPair, event any) (string, error) {
	key, err := c.GetCaller(caller)
	if err != nil {
		return "", errors.Wrap(err, "delete user file error")
	}
	if caller == nil {
		defer c.PutKey(key.Address)
	}

	newcall, err := types.NewCall(c.Metadata, "FileBank.delete_file", owner, fid)
	if err != nil {
		return "", errors.Wrap(err, "delete user file error")
	}

	blockhash, err := c.SubmitExtrinsic(key, newcall, "FileBank.DeleteFile", event, c.Timeout)
	if err != nil {
		return blockhash, errors.Wrap(err, "delete user file error")
	}

	return blockhash, nil
}
