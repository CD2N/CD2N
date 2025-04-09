package chain

import "github.com/centrifuge/go-substrate-rpc-client/v4/types"

// ------------------------FileBank----------------------
type EventDeleteFile struct {
	Phase    types.Phase
	Operator types.AccountID
	Owner    types.AccountID
	Filehash []FileHash
	Topics   []types.Hash
}

type EventFillerDelete struct {
	Phase      types.Phase
	Acc        types.AccountID
	FillerHash FileHash
	Topics     []types.Hash
}

type EventUploadDeclaration struct {
	Phase    types.Phase
	Operator types.AccountID
	Owner    types.AccountID
	DealHash FileHash
	Topics   []types.Hash
}

type EventIncreaseDeclarationSpace struct {
	Phase  types.Phase
	Miner  types.AccountID
	Space  types.U128
	Topics []types.Hash
}

// ------------------------StorageHandler--------------------------------
type EventBuySpace struct {
	Phase            types.Phase
	Acc              types.AccountID
	Storage_capacity types.U128
	Spend            types.U128
	Topics           []types.Hash
}

type EventExpansionSpace struct {
	Phase           types.Phase
	Acc             types.AccountID
	Expansion_space types.U128
	Fee             types.U128
	Topics          []types.Hash
}

type EventRenewalSpace struct {
	Phase       types.Phase
	Acc         types.AccountID
	RenewalDays types.U32
	Fee         types.U128
	Topics      []types.Hash
}

type EventPaidOrder struct {
	Phase     types.Phase
	OrderHash []types.U8
	Topics    []types.Hash
}

type EventCreatePayOrder struct {
	Phase     types.Phase
	OrderHash []types.U8
	Topics    []types.Hash
}
