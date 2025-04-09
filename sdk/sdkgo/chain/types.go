package chain

import (
	"bytes"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/vedhavyas/go-subkey/scale"
)

type FileHash [64]types.U8
type AccBytes [256]types.U8
type BloomFilter [256]types.U64

type StorageOrder struct {
	FileSize     types.U128
	SegmentList  []SegmentList
	User         UserBrief
	CompleteList []CompleteInfo
}

type UserFileSliceInfo struct {
	TerritoryName types.Bytes
	Filehash      FileHash
	FileSize      types.U128
}

type SegmentList struct {
	SegmentHash  FileHash
	FragmentHash []FileHash
}

type CompleteInfo struct {
	Index types.U8
	Miner types.AccountID
}

type FileMetadata struct {
	SegmentList []SegmentInfo
	Owner       []UserBrief
	FileSize    types.U128
	Completion  types.U32
	State       types.U8
}

type SegmentInfo struct {
	Hash         FileHash
	FragmentList []FragmentInfo
}

type FragmentInfo struct {
	Hash  FileHash
	Avail types.Bool
	Tag   types.Option[types.U32]
	Miner types.AccountID
}

type UserBrief struct {
	User          types.AccountID
	FileName      types.Bytes
	TerriortyName types.Bytes
}

type TerritoryInfo struct {
	Token          types.H256
	TotalSpace     types.U128
	UsedSpace      types.U128
	LockedSpace    types.U128
	RemainingSpace types.U128
	Start          types.U32
	Deadline       types.U32
	State          types.U8 //0: Active 1: Frozen 2: Expired 3: OnConsignment
}

type MinerInfo struct {
	BeneficiaryAccount types.AccountID
	StakingAccount     types.AccountID
	Endpoint           types.Bytes
	Collaterals        types.U128
	Debt               types.U128
	State              types.Bytes // positive, exit, frozen, lock
	DeclarationSpace   types.U128
	IdleSpace          types.U128
	ServiceSpace       types.U128
	LockSpace          types.U128
	SpaceProofInfo     types.Option[SpaceProofInfo]
	ServiceBloomFilter BloomFilter
	TeeSig             [64]types.U8
}

type SpaceProofInfo struct {
	Miner       types.AccountID
	Front       types.U64
	Rear        types.U64
	PoisKey     PoISKeyInfo
	Accumulator AccBytes
}

type PoISKeyInfo struct {
	G AccBytes
	N AccBytes
}

type BucketInfo struct {
	FileList  []FileHash
	Authority []types.AccountID
}

type OssInfo struct {
	Peerid [38]types.U8
	Domain types.Bytes
}

type SignPayload struct {
	Oss types.AccountID
	Exp types.U32
}

func (p SignPayload) EncodeSignPayload() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	s := scale.NewEncoder(buf)
	err := s.Encode(p)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
