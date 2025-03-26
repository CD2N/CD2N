package retriever

import (
	"github.com/CD2N/CD2N/sdk/sdkgo/chain"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/pkg/errors"
)

func QueryDealMap(cli *chain.Client, fid string) (map[int]struct{}, error) {
	cmpSet := make(map[int]struct{})
	order, err := cli.QueryDealMap(fid, 0)
	if err != nil {
		return cmpSet, errors.Wrap(err, "query file deal map on chain error")
	}
	for _, c := range order.CompleteList {
		cmpSet[int(c.Index)] = struct{}{}
	}
	return cmpSet, nil
}

func CreateStorageOrder(cli *chain.Client, info FileInfo, caller *signature.KeyringPair, event any) (string, error) {
	var (
		segments []chain.SegmentList
		user     chain.UserBrief
	)
	for i, v := range info.Fragments {
		segment := chain.SegmentList{
			SegmentHash:  getFileHash(info.Segments[i]),
			FragmentHash: make([]chain.FileHash, len(v)),
		}
		for j, fragment := range v {
			segment.FragmentHash[j] = getFileHash(fragment)
		}
		segments = append(segments, segment)
	}
	acc, err := types.NewAccountID(info.Owner)
	if err != nil {
		return "", errors.Wrap(err, "create storage order error")
	}
	user.User = *acc
	user.FileName = types.NewBytes([]byte(info.FileName))
	user.TerriortyName = types.NewBytes([]byte(info.Territory))
	hash, err := cli.UploadDeclaration(getFileHash(info.Fid), segments, user, uint64(info.FileSize), caller, event)
	if err != nil {
		return hash, errors.Wrap(err, "create storage order error")
	}
	return hash, nil
}

func getFileHash(fid string) chain.FileHash {
	var hash chain.FileHash
	for i := 0; i < len(fid) && i < len(hash); i++ {
		hash[i] = types.U8(fid[i])
	}
	return hash
}
