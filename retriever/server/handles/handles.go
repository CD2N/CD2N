package handles

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/CD2N/CD2N/retriever/config"
	"github.com/CD2N/CD2N/retriever/gateway"
	"github.com/CD2N/CD2N/retriever/libs/buffer"
	"github.com/CD2N/CD2N/retriever/libs/cache"
	"github.com/CD2N/CD2N/retriever/libs/chain"
	"github.com/CD2N/CD2N/retriever/libs/client"
	"github.com/CD2N/CD2N/retriever/logger"
	"github.com/CD2N/CD2N/retriever/node"
	"github.com/CD2N/CD2N/retriever/utils"
	"github.com/decred/base58"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/vedhavyas/go-subkey"
	"golang.org/x/crypto/blake2b"
)

type ServerHandle struct {
	node        *node.Manager
	gateway     *gateway.Gateway
	buffer      *buffer.FileBuffer
	partRecord  *leveldb.DB
	filepartMap *sync.Map
	teeEndpoint string
	teePubkey   []byte
	teeAddr     string
	poolId      string
}

type PartsInfo struct {
	ShadowHash string    `json:"shadow_hash,omitempty"`
	FileName   string    `json:"file_name,omitempty"`
	DirName    string    `json:"dir_name,omitempty"`
	Archive    string    `json:"archive,omitempty"`
	Owner      []byte    `json:"owner,omitempty"`
	Territory  string    `json:"territory,omitempty"`
	Parts      []string  `json:"parts,omitempty"`
	PartsCount int       `json:"parts_count,omitempty"`
	TotalParts int       `json:"total_parts,omitempty"`
	TotalSize  int64     `json:"total_size,omitempty"`
	UpdateDate time.Time `json:"update_date,omitempty"`
}

func NewServerHandle() *ServerHandle {
	return &ServerHandle{
		filepartMap: &sync.Map{},
	}
}

func (h *ServerHandle) InitHandlesRuntime(ctx context.Context) error {
	conf := config.GetConfig()
	if conf.PoolName == "" {
		conf.PoolName = config.DEFAULT_CD2N_POOLID
	}
	h.poolId = base58.Encode([]byte(conf.PoolName))

	if !conf.Debug {
		h.teeEndpoint = conf.TeeAddress
		u, err := url.JoinPath(h.teeEndpoint, client.QUERY_TEE_INFO)
		if err != nil {
			return errors.Wrap(err, "init handles runtime error")
		}
		var data client.TeeResp
		for i := 0; i < 5; i++ {
			data, err = client.QueryTeeInfo(u)
			if err == nil && data.EthAddress != "" {
				break
			}
			time.Sleep(time.Second * 6)
		}
		if err != nil {
			return errors.Wrap(err, "init handles runtime error")
		}
		h.teeAddr = data.EthAddress
		h.teePubkey = data.Pubkey
		go func() {
			ticker := time.NewTicker(time.Hour * 24 * 25)
			for {
				err := h.RechargeGasFeeForTEE(h.teeAddr, conf)
				if err != nil {
					log.Println(err)
					time.Sleep(time.Minute * 15)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	} else {
		h.teeEndpoint = "http://139.180.142.180:1309"
	}

	// build workspace
	if err := BuildWorkspace(conf.WorkSpace); err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	// init level databases
	if err := client.RegisterLeveldbCli(
		filepath.Join(conf.WorkSpace, config.LEVELDB_DIR),
		config.TASKDB_NAME, config.CIDMAPDB_NAME,
	); err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	h.partRecord = client.GetLeveldbCli(config.TASKDB_NAME)

	// register nodes
	contractCli, err := h.registerNode(conf)
	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	//init cd2n base module
	ipfsCli, err := client.NewIpfsClient(conf.IpfsAddress)
	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	redisCli := client.NewRedisClient(fmt.Sprintf("localhost:%d", conf.RedisPort), conf.RedisPwd)

	h.buffer, err = buffer.NewFileBuffer(
		uint64(conf.FileBufferSize),
		filepath.Join(conf.WorkSpace, config.DATA_BUFFER_DIR),
	)
	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	ipfsFileCacher := cache.NewCache(uint64(conf.IpfsDiskSize))

	ipfsFileCacher.RegisterSwapoutCallbacksCallbacks(func(i cache.Item) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		err := client.RemoveFileFromIpfs(ipfsCli, ctx, i.Key)
		if err != nil {
			logger.GetLogger(config.LOG_RETRIEVE).Error(err)
		}
	})

	// init nodes
	h.node = node.NewManager(
		redisCli, ipfsCli,
		client.GetLeveldbCli(config.CIDMAPDB_NAME),
		ipfsFileCacher, h.buffer, contractCli.Node.Hex(),
	)

	// run message pubsub
	go func() {
		for i := 0; i < 5; i++ {
			err = h.node.SubscribeCidMap(ctx, h.poolId)
			if err != nil {
				log.Println("subscribe cid map failed", err)
			}
			time.Sleep(time.Minute)
		}
	}()
	go h.node.CallbackManager(ctx)

	if !conf.LaunchGateway {
		return nil
	}

	// init gateway, if it be needed
	fileCacher, err := buffer.NewFileBuffer(
		uint64(conf.GatewayCacheSize),
		filepath.Join(conf.WorkSpace, config.FILE_CACHE_DIR),
	)
	if err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	if h.gateway, err = gateway.NewGateway(
		redisCli, contractCli, fileCacher,
		client.GetLeveldbCli(config.TASKDB_NAME),
	); err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	//register oss node on chain
	if err = h.registerOssNode(conf); err != nil {
		return errors.Wrap(err, "init handles runtime error")
	}

	go func() {
		err = h.gateway.ProvideTaskChecker(ctx, h.buffer)
		if err != nil {
			log.Fatal("run providing task checker error", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(time.Minute * 15)
		if err = h.gateway.LoadCdnNodes(); err != nil {
			log.Println(err)
		}
		count := 0
		for range ticker.C {
			if err = h.gateway.LoadCdnNodes(); err != nil {
				count++
				if count%8 == 0 { //print error log per 2 hours
					log.Println(err)
					count = 0
				}
			}
		}
	}()
	return nil
}

func (h *ServerHandle) RechargeGasFeeForTEE(addr string, conf config.Config) error {
	bytesAddr := common.HexToAddress(addr).Bytes()
	data := append([]byte("evm:"), bytesAddr...)
	hashed := blake2b.Sum256(data)
	cessAcc := subkey.SS58Encode(hashed[:], uint16(conf.ChainId))

	cli, err := chain.NewCessChainClient(context.Background(), conf.Mnemonic, conf.Rpcs)
	if err != nil {
		return errors.Wrap(err, "check and transfer gas free error")
	}
	account, err := utils.ParsingPublickey(cessAcc)

	info, err := cli.QueryAccountInfoByAccountID(account, -1)
	if err != nil {
		return errors.Wrap(err, "check and transfer gas free error")
	}
	flag, _ := big.NewInt(0).SetString("1000000000000000000000", 10)
	if info.Data.Free.Cmp(flag) >= 0 {
		return nil
	}
	_, err = cli.TransferToken(cessAcc, "1000000000000000000000")
	return errors.Wrap(err, "check and transfer gas free error")
}

func (h *ServerHandle) registerOssNode(conf config.Config) error {
	cli, err := h.gateway.GetCessClient()
	if err != nil {
		return errors.Wrap(err, "register OSS node on chain error")
	}
	if _, err = cli.QueryOss(cli.GetSignatureAccPulickey(), -1); err == nil {
		return nil
	}
	hash, err := cli.RegisterOss(conf.Endpoint)
	if err != nil {
		return errors.Wrap(err, "register OSS node on chain error")
	}
	log.Println("register OSS node success, tx hash:", hash)
	return nil
}

func (h *ServerHandle) registerNode(conf config.Config) (*chain.CacheProtoContract, error) {
	cli, err := chain.NewClient(
		chain.AccountPrivateKey(conf.SecretKey),
		chain.ChainID(conf.ChainId),
		chain.ConnectionRpcAddresss(conf.Rpcs),
		chain.EthereumGas(conf.GasFreeCap, conf.GasLimit),
	)
	if err != nil {
		return nil, errors.Wrap(err, "register node error")
	}

	contract, err := chain.NewProtoContract(
		cli.GetEthClient(),
		conf.ProtoContract,
		conf.SecretKey,
		cli.NewTransactionOption,
		cli.SubscribeFilterLogs,
	)
	if err != nil {
		return nil, errors.Wrap(err, "register node error")
	}
	if conf.Debug {
		return contract, nil
	}
	info, err := contract.QueryRegisterInfo(cli.Account)
	if err == nil && len(info.TeeEth.Bytes()) > 0 {
		return contract, nil
	}
	sign, err := hex.DecodeString(conf.TokenAccSign)
	if err != nil {
		return nil, errors.Wrap(err, "register node error")
	}
	if err = contract.RegisterNode(context.Background(), chain.RegisterReq{
		NodeAcc:   cli.Account,
		TokenAcc:  common.HexToAddress(conf.TokenAcc),
		Endpoint:  conf.Endpoint,
		TokenId:   conf.Token,
		Signature: sign,
		TeeEth:    common.HexToAddress(h.teeAddr),
		TeeCess:   h.teePubkey,
	}); err != nil {
		return nil, errors.Wrap(err, "register node error")
	}

	return contract, nil
}

func BuildWorkspace(workspace string) error {

	if _, err := os.Stat(workspace); err != nil {
		if err = os.MkdirAll(workspace, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	cacheDir := filepath.Join(workspace, config.FILE_CACHE_DIR)
	if _, err := os.Stat(cacheDir); err != nil {
		if err = os.Mkdir(cacheDir, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}

	bufferDir := filepath.Join(workspace, config.DATA_BUFFER_DIR)
	if _, err := os.Stat(bufferDir); err != nil {
		if err = os.Mkdir(bufferDir, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}

	dbDir := filepath.Join(workspace, config.LEVELDB_DIR)
	if _, err := os.Stat(dbDir); err != nil {
		if err = os.Mkdir(dbDir, 0755); err != nil {
			return errors.Wrap(err, "build workspace error")
		}
	}
	return nil
}

func (h *ServerHandle) GetNodeInfo(c *gin.Context) {
	conf := config.GetConfig()
	c.JSON(http.StatusOK,
		client.NewResponse(http.StatusOK, "succes", client.Cd2nNode{
			WorkAddr:  h.node.GetNodeAddress(),
			TeeAddr:   h.teeAddr,
			TeePubkey: h.teePubkey,
			IsGateway: h.gateway != nil,
			PoolId:    h.poolId,
			EndPoint:  conf.Endpoint,
			RedisAddr: conf.RedisAddress,
		}))
}
