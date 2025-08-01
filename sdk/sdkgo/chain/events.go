package chain

import (
	"reflect"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

var (
	CommonEventsTypeMap = map[string]reflect.Type{

		// Treasury
		"Treasury.Burnt":           reflect.TypeOf(types.EventTreasuryBurnt{}),
		"Treasury.Awarded":         reflect.TypeOf(types.EventTreasuryAwarded{}),
		"Treasury.SpendApproved":   reflect.TypeOf(types.EventTreasurySpendApproved{}),
		"Treasury.Deposit":         reflect.TypeOf(types.EventTreasuryDeposit{}),
		"Treasury.Spending":        reflect.TypeOf(types.EventTreasurySpending{}),
		"Treasury.UpdatedInactive": reflect.TypeOf(types.EventTreasuryUpdatedInactive{}),
		"Treasury.Rollover":        reflect.TypeOf(types.EventTreasuryRollover{}),

		// System
		"System.UpgradeAuthorized": reflect.TypeOf(types.EventParachainSystemUpgradeAuthorized{}),
		"System.ExtrinsicSuccess":  reflect.TypeOf(types.EventSystemExtrinsicSuccess{}),
		"System.ExtrinsicFailed":   reflect.TypeOf(types.EventSystemExtrinsicFailed{}),

		// Balances
		"Balances.Slashed":    reflect.TypeOf(types.EventBalancesSlashed{}),
		"Balances.Deposit":    reflect.TypeOf(types.EventBalancesDeposit{}),
		"Balances.Withdraw":   reflect.TypeOf(types.EventBalancesWithdraw{}),
		"Balances.Unreserved": reflect.TypeOf(types.EventBalancesUnreserved{}),
		"Balances.BalanceSet": reflect.TypeOf(types.EventBalancesBalanceSet{}),
		"Balances.Transfer":   reflect.TypeOf(types.EventBalancesTransfer{}),
		"Balances.Reserved":   reflect.TypeOf(types.EventBalancesReserved{}),

		// TransactionPayment
		"TransactionPayment.TransactionFeePaid": reflect.TypeOf(types.EventTransactionPaymentTransactionFeePaid{}),

		// Audit
		"Audit.SubmitServiceProof":        reflect.TypeOf(EventSubmitServiceProof{}),
		"Audit.GenerateChallenge":         reflect.TypeOf(EventGenerateChallenge{}),
		"Audit.VerifyProof":               reflect.TypeOf(EventVerifyProof{}),
		"Audit.SubmitIdleVerifyResult":    reflect.TypeOf(EventSubmitIdleVerifyResult{}),
		"Audit.SubmitServiceVerifyResult": reflect.TypeOf(EventSubmitServiceVerifyResult{}),
		"Audit.SubmitIdleProof":           reflect.TypeOf(EventSubmitIdleProof{}),

		// Sminer
		"Sminer.MinerExitPrep":            reflect.TypeOf(EventMinerExitPrep{}),
		"Sminer.RegisterPoisKey":          reflect.TypeOf(EventRegisterPoisKey{}),
		"Sminer.Deposit":                  reflect.TypeOf(EventDeposit{}),
		"Sminer.LessThan24Hours":          reflect.TypeOf(EventLessThan24Hours{}),
		"Sminer.FaucetTopUpMoney":         reflect.TypeOf(EventFaucetTopUpMoney{}),
		"Sminer.IncreaseCollateral":       reflect.TypeOf(EventIncreaseCollateral{}),
		"Sminer.Receive":                  reflect.TypeOf(EventReceive{}),
		"Sminer.UpdateBeneficiary":        reflect.TypeOf(EventUpdateBeneficiary{}),
		"Sminer.AlreadyFrozen":            reflect.TypeOf(EventAlreadyFrozen{}),
		"Sminer.DrawFaucetMoney":          reflect.TypeOf(EventDrawFaucetMoney{}),
		"Sminer.Registered":               reflect.TypeOf(EventRegistered{}),
		"Sminer.IncreaseDeclarationSpace": reflect.TypeOf(EventIncreaseDeclarationSpace{}),
		//"Sminer.DecreaseDeclarationSpace": reflect.TypeOf(),
		//"Sminer.UpdateEndPoint":           reflect.TypeOf(),
		//"Sminer.Withdraw":                 reflect.TypeOf(),

		// TeeWorker
		"TeeWorker.MasterKeyLaunched":             reflect.TypeOf(EventMasterKeyLaunched{}),
		"TeeWorker.WorkerAdded":                   reflect.TypeOf(EventWorkerAdded{}),
		"TeeWorker.WorkerUpdated":                 reflect.TypeOf(EventWorkerUpdated{}),
		"TeeWorker.MinimumCesealVersionChangedTo": reflect.TypeOf(EventMinimumCesealVersionChangedTo{}),
		// "TeeWorker.MasterKeyHolderChanged": reflect.TypeOf(),
		//"TeeWorker.ClearInvalidTee": reflect.TypeOf(),
		//"TeeWorker.MasterKeyAppling": reflect.TypeOf(),
		//"TeeWorker.CesealBinRemoved": reflect.TypeOf(),
		//"TeeWorker.MasterKeyLaunching": reflect.TypeOf(),
		//"TeeWorker.CesealBinAdded": reflect.TypeOf(),
		//"TeeWorker.MasterKeySubmitted": reflect.TypeOf(),

		// OSS
		"Oss.OssUpdate":       reflect.TypeOf(EventOssUpdate{}),
		"Oss.OssDestroy":      reflect.TypeOf(EventOssDestroy{}),
		"Oss.CancelAuthorize": reflect.TypeOf(EventCancelAuthorize{}),
		"Oss.OssRegister":     reflect.TypeOf(EventOssRegister{}),
		"Oss.Authorize":       reflect.TypeOf(EventAuthorize{}),

		// FileBank
		"FileBank.UploadDeclaration":     reflect.TypeOf(EventUploadDeclaration{}),
		"FileBank.DeleteFile":            reflect.TypeOf(EventDeleteFile{}),
		"FileBank.TerritoryFileDelivery": reflect.TypeOf(EventTerritorFileDelivery{}),
		"FileBank.ReplaceIdleSpace":      reflect.TypeOf(EventReplaceIdleSpace{}),
		"FileBank.ReplaceFiller":         reflect.TypeOf(EventReplaceFiller{}),
		"FileBank.ClaimRestoralOrder":    reflect.TypeOf(EventClaimRestoralOrder{}),
		"FileBank.GenerateRestoralOrder": reflect.TypeOf(EventGenerateRestoralOrder{}),
		"FileBank.CalculateReport":       reflect.TypeOf(EventCalculateReport{}),
		"FileBank.RecoveryCompleted":     reflect.TypeOf(EventRecoveryCompleted{}),
		"FileBank.StorageCompleted":      reflect.TypeOf(EventStorageCompleted{}),
		"FileBank.TransferReport":        reflect.TypeOf(EventTransferReport{}),
		"FileBank.IdleSpaceCert":         reflect.TypeOf(EventIdleSpaceCert{}),

		//StorageHandler
		"StorageHandler.ExpansionSpace":       reflect.TypeOf(EventExpansionSpace{}),
		"StorageHandler.RenewalSpace":         reflect.TypeOf(EventRenewalSpace{}),
		"StorageHandler.PaidOrder":            reflect.TypeOf(EventPaidOrder{}),
		"StorageHandler.CreatePayOrder":       reflect.TypeOf(EventCreatePayOrder{}),
		"StorageHandler.BuySpace":             reflect.TypeOf(EventBuySpace{}),
		"StorageHandler.LeaseExpired":         reflect.TypeOf(EventLeaseExpired{}),
		"StorageHandler.LeaseExpireIn24Hours": reflect.TypeOf(EventLeaseExpireIn24Hours{}),
		//"StorageHandler.BuyConsignment":       reflect.TypeOf(),
		//"StorageHandler.Consignment":       reflect.TypeOf(),
		//"StorageHandler.ExpansionTerritory":       reflect.TypeOf(),
		//"StorageHandler.CancleConsignment":       reflect.TypeOf({}),
		//"StorageHandler.RenewalTerritory":       reflect.TypeOf(),
		//"StorageHandler.ExecConsignment":       reflect.TypeOf({}),
		//"StorageHandler.ReactivateTerritory":       reflect.TypeOf({}),
		//"StorageHandler.MintTerritory":       reflect.TypeOf(),
		//"StorageHandler.CancelPurchaseAction":       reflect.TypeOf({}),
	}
)

// ------------------------Audit-------------------
type EventVerifyProof struct {
	Phase     types.Phase
	TeeWorker [32]types.U8
	Miner     types.AccountID
	Topics    []types.Hash
}

type EventSubmitProof struct {
	Phase  types.Phase
	Miner  types.AccountID
	Topics []types.Hash
}

type EventGenerateChallenge struct {
	Phase  types.Phase
	Miner  types.AccountID
	Topics []types.Hash
}

type EventSubmitIdleProof struct {
	Phase  types.Phase
	Miner  types.AccountID
	Topics []types.Hash
}

type EventSubmitServiceProof struct {
	Phase  types.Phase
	Miner  types.AccountID
	Topics []types.Hash
}

type EventSubmitIdleVerifyResult struct {
	Phase  types.Phase
	Tee    [32]types.U8
	Miner  types.AccountID
	Result types.Bool
	Topics []types.Hash
}

type EventSubmitServiceVerifyResult struct {
	Phase  types.Phase
	Tee    [32]types.U8
	Miner  types.AccountID
	Result types.Bool
	Topics []types.Hash
}

// ------------------------Sminer------------------------
type EventRegistered struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventRegisterPoisKey struct {
	Phase  types.Phase
	Miner  types.AccountID
	Topics []types.Hash
}

type EventDrawFaucetMoney struct {
	Phase  types.Phase
	Topics []types.Hash
}

type EventFaucetTopUpMoney struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventLessThan24Hours struct {
	Phase  types.Phase
	Last   types.U32
	Now    types.U32
	Topics []types.Hash
}
type EventAlreadyFrozen struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventMinerExit struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventMinerClaim struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventIncreaseCollateral struct {
	Phase   types.Phase
	Acc     types.AccountID
	Balance types.U128
	Topics  []types.Hash
}

type EventDeposit struct {
	Phase   types.Phase
	Balance types.U128
	Topics  []types.Hash
}

type EventUpdateBeneficiary struct {
	Phase  types.Phase
	Acc    types.AccountID
	New    types.AccountID
	Topics []types.Hash
}

type EventReceive struct {
	Phase  types.Phase
	Acc    string
	Reward types.U128
	Topics []types.Hash
}

type EventMinerExitPrep struct {
	Phase  types.Phase
	Miner  types.AccountID
	Topics []types.Hash
}

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

type EventFillerUpload struct {
	Phase    types.Phase
	Acc      types.AccountID
	Filesize types.U64
	Topics   []types.Hash
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

type EventTransferReport struct {
	Phase    types.Phase
	Acc      types.AccountID
	DealHash FileHash
	Topics   []types.Hash
}

type EventReplaceFiller struct {
	Phase       types.Phase
	Acc         types.AccountID
	Filler_list []FileHash
	Topics      []types.Hash
}

type EventCalculateEnd struct {
	Phase     types.Phase
	File_hash FileHash
	Topics    []types.Hash
}

type EventGenerateRestoralOrder struct {
	Phase        types.Phase
	Miner        types.AccountID
	FragmentHash FileHash
	Topics       []types.Hash
}

type EventClaimRestoralOrder struct {
	Phase   types.Phase
	Miner   types.AccountID
	OrderId FileHash
	Topics  []types.Hash
}

type EventRecoveryCompleted struct {
	Phase   types.Phase
	Miner   types.AccountID
	OrderId FileHash
	Topics  []types.Hash
}

type EventStorageCompleted struct {
	Phase    types.Phase
	FileHash FileHash
	Topics   []types.Hash
}

type EventWithdraw struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventIdleSpaceCert struct {
	Phase  types.Phase
	Acc    types.AccountID
	Space  types.U128
	Topics []types.Hash
}

type EventReplaceIdleSpace struct {
	Phase  types.Phase
	Acc    types.AccountID
	Space  types.U128
	Topics []types.Hash
}

type EventCalculateReport struct {
	Phase    types.Phase
	Miner    types.AccountID
	FileHash FileHash
	Topics   []types.Hash
}

type EventTerritorFileDelivery struct {
	Phase        types.Phase
	Filehash     FileHash
	NewTerritory types.Bytes
	Topics       []types.Hash
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

type EventLeaseExpired struct {
	Phase  types.Phase
	Acc    types.AccountID
	Size   types.U128
	Topics []types.Hash
}

type EventLeaseExpireIn24Hours struct {
	Phase  types.Phase
	Acc    types.AccountID
	Size   types.U128
	Topics []types.Hash
}

// ------------------------TEE Worker--------------------
type EventExit struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventMasterKeyLaunched struct {
	Phase  types.Phase
	Topics []types.Hash
}

type EventWorkerAdded struct {
	Phase               types.Phase
	Pubkey              [32]types.U8
	AttestationProvider types.Option[types.U8]
	ConfidenceLevel     types.U8
	Topics              []types.Hash
}

type EventKeyfairyAdded struct {
	Phase  types.Phase
	Pubkey [32]types.U8
	Topics []types.Hash
}

type EventWorkerUpdated struct {
	Phase               types.Phase
	Pubkey              [32]types.U8
	AttestationProvider types.Option[types.U8]
	ConfidenceLevel     types.U8
	Topics              []types.Hash
}

type EventMasterKeyRotated struct {
	Phase        types.Phase
	RotationId   types.U64
	MasterPubkey [32]types.U8
	Topics       []types.Hash
}

type EventMasterKeyRotationFailed struct {
	Phase              types.Phase
	RotationLock       types.Option[types.U64]
	KeyfairyRotationId types.U64
	Topics             []types.Hash
}

type EventMinimumCesealVersionChangedTo struct {
	Phase  types.Phase
	Elem1  types.U32
	Elem2  types.U32
	Elem3  types.U32
	Topics []types.Hash
}

// ------------------------Oss---------------------------
type EventOssRegister struct {
	Phase    types.Phase
	Acc      types.AccountID
	Endpoint [38]types.U8
	Topics   []types.Hash
}

type EventOssUpdate struct {
	Phase       types.Phase
	Acc         types.AccountID
	NewEndpoint [38]types.U8
	Topics      []types.Hash
}

type EventOssDestroy struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

type EventAuthorize struct {
	Phase    types.Phase
	Acc      types.AccountID
	Operator types.AccountID
	Topics   []types.Hash
}

type EventCancelAuthorize struct {
	Phase  types.Phase
	Acc    types.AccountID
	Topics []types.Hash
}

// ------------------------system------------------------
type EventElectionFinalized struct {
	Phase   types.Phase
	Compute types.U8
	Score   ElectionScore
	Topics  []types.Hash
}

type EventPhaseTransitioned struct {
	Phase  types.Phase
	From   Signed
	To     Unsigneds
	Round  types.U32
	Topics []types.Hash
}

type Signed struct {
	Index types.U8
	Value types.U32
}

type Unsigneds struct {
	Index         types.U8
	UnsignedValue []UnsignedValue
}

type UnsignedValue struct {
	Bool types.Bool
	Bn   types.U32
}

type EventSolutionStored struct {
	Phase       types.Phase
	Compute     ElectionCompute
	Origin      types.Option[types.AccountID]
	PrevEjected types.Bool
	Topics      []types.Hash
}

type ElectionCompute struct {
	Index types.U8
	Value types.U8
}

type EventLocked struct {
	Phase  types.Phase
	Who    types.AccountID
	Amount types.U128
	Topics []types.Hash
}

type EventServiceFeePaid struct {
	Phase       types.Phase
	Who         types.AccountID
	ActualFee   types.U128
	ExpectedFee types.U128
	Topics      []types.Hash
}

type EventCallDone struct {
	Phase      types.Phase
	Who        types.AccountID
	CallResult Result
	Topics     []types.Hash
}

type Result struct {
	Index    types.U8
	ResultOk ResultOk
}

type ResultOk struct {
	ActualWeight types.Option[ActualWeightType]
	PaysFee      types.U8
}

type ActualWeightType struct {
	RefTime   types.U64
	ProofSize types.U64
}

type EventValidatorPrefsSet struct {
	Phase  types.Phase
	Stash  types.AccountID
	Prefs  ValidatorPrefs
	Topics []types.Hash
}

type ValidatorPrefs struct {
	Commission types.U32
	Blocked    types.Bool
}

// *******************************************************
type ElectionScore struct {
	/// The minimal winner, in terms of total backing stake.
	///
	/// This parameter should be maximized.
	Minimal_stake types.U128
	/// The sum of the total backing of all winners.
	///
	/// This parameter should maximized
	Sum_stake types.U128
	/// The sum squared of the total backing of all winners, aka. the variance.
	///
	/// Ths parameter should be minimized.
	Sum_stake_squared types.U128
}
