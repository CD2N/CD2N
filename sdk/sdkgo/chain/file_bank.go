package chain

import (
	"math/big"

	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/pkg/errors"
)

// QueryDealMap retrieves the storage order information for a specific file by its file ID.
// Validates file ID format (64-byte hex string), encodes it to file hash, and queries the FileBank storage.
// Parameters:
//
//	fid - 64-byte hex string representing the file ID
//	block - Block number to query (0 for latest block)
//
// Returns:
//
//	StorageOrder struct containing file storage details
//	Error if file ID is invalid, encoding fails, or storage query fails
func (c *Client) QueryDealMap(fid string, block uint32) (StorageOrder, error) {
	var (
		data StorageOrder
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
	data, err = QueryStorage[StorageOrder](c, block, "FileBank", "DealMap", h)
	if err != nil {
		return data, errors.Wrap(err, "query deal map error")
	}
	return data, nil
}

// QueryFileMetadata fetches metadata (e.g., file size, creation time) for a specific file.
// Validates file ID format, encodes to file hash, and queries the FileBank file metadata storage.
// Parameters:
//
//	fid - 64-byte hex string representing the file ID
//	block - Block number to query (0 for latest block)
//
// Returns:
//
//	FileMetadata struct containing file metadata
//	Error if file ID is invalid, encoding fails, or storage query fails
func (c *Client) QueryFileMetadata(fid string, block uint32) (FileMetadata, error) {
	var (
		data FileMetadata
		hash FileHash
	)
	if fid == "" || len(fid) != 64 {
		return data, errors.Wrap(errors.New("bad fid"), "query file metadata error")
	}
	for i := range len(fid) {
		hash[i] = types.U8(fid[i])
	}
	h, err := codec.Encode(hash)
	if err != nil {
		return data, errors.Wrap(err, "query file metadata error")
	}
	data, err = QueryStorage[FileMetadata](c, block, "FileBank", "File", h)
	if err != nil {
		return data, errors.Wrap(err, "query file metadata error")
	}
	return data, nil
}

// QueryUserFileList retrieves the list of files held by a specific user.
// Converts account ID to AccountID type, encodes it, and queries the user's file list storage.
// Parameters:
//
//	accountID - Raw byte slice representing the user's account ID
//	block - Block number to query (0 for latest block)
//
// Returns:
//
//	Slice of UserFileSliceInfo containing file slice details
//	Error if account ID conversion fails, encoding fails, or storage query fails
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

// UploadDeclaration submits a file upload declaration transaction to the blockchain.
// Signs and submits the extrinsic with file hash, segment info, user details, and file size.
// Parameters:
//
//	fid - FileHash struct representing the file's cryptographic hash
//	segment - Slice of SegmentList containing file segment details
//	user - UserBrief struct with user identification information
//	filesize - Total size of the file in bytes (uint64)
//	caller - Keyring pair for transaction signing (optional, uses client's keyring if nil)
//	event - Event pointer, used to receive FileBank.UploadDeclaration event
//
// Returns:
//
//	Block hash where the transaction was included
//	Error if signing, extrinsic creation, or submission fails
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

// DeleteUserFile submits a file deletion transaction to remove a user's file.
// Signs and submits the extrinsic with file hash and owner's account ID.
// Parameters:
//
//	fid - FileHash struct representing the file's cryptographic hash
//	owner - AccountID of the file owner
//	caller - Keyring pair for transaction signing (optional, uses client's keyring if nil)
//	event - Event pointer, used to receive FileBank.DeleteFile event
//
// Returns:
//
//	Block hash where the transaction was included
//	Error if signing, extrinsic creation, or submission fails
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
