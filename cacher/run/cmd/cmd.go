package cmd

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CD2N/CD2N/cacher/chain"
	"github.com/CD2N/CD2N/cacher/client"
	"github.com/CD2N/CD2N/cacher/config"
	"github.com/CD2N/CD2N/cacher/logger"
	"github.com/CD2N/CD2N/cacher/manager"
	"github.com/CD2N/CD2N/sdk/sdkgo/libs/cache"
	"github.com/ethereum/go-ethereum/common"
	"github.com/go-redis/redis/v8"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "Cacher",
	Short: "Cacher is the L2 node of CD2N, responsible for providing data to the master node.",
}

func Execute() {
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func InitCmd() {
	rootCmd.AddCommand(
		cmd_run(),
		cmd_exit_network(),
	)
	rootCmd.PersistentFlags().StringP("config", "c", "", "custom profile")
}

func cmd_run() *cobra.Command {
	return &cobra.Command{
		Use:                   "run",
		Short:                 "Running services",
		DisableFlagsInUseLine: true,
		Run:                   cmd_run_func,
	}
}

func cmd_exit_network() *cobra.Command {
	return &cobra.Command{
		Use:                   "exit",
		Short:                 "exit node from CD2N network and redeem staking",
		DisableFlagsInUseLine: true,
		Run:                   cmd_exit_func,
	}
}

func cmd_exit_func(cmd *cobra.Command, args []string) {
	cpath, _ := cmd.Flags().GetString("config")
	if cpath == "" {
		cpath, _ = cmd.Flags().GetString("c")
		if cpath == "" {
			logger.GetGlobalLogger().GetLogger(config.LOG_NODE).Error("empty config file path")
			log.Println("empty config file path")
			return
		}
	}

	if err := config.InitDefaultConfig(cpath); err != nil {
		log.Println("error", err)
		return
	}
	conf := config.GetConfig()
	cli, err := chain.NewClient(
		chain.AccountPrivateKey(conf.SecretKey),
		chain.ChainID(conf.ChainId),
		chain.ConnectionRpcAddresss(conf.Rpcs),
		chain.EthereumGas(conf.GasFreeCap, conf.GasLimit),
	)
	if err != nil {
		log.Fatal(err)
	}

	contract, err := chain.NewProtoContract(
		cli.GetEthClient(),
		conf.ProtoContract,
		cli.Account.Hex(),
		cli.NewTransactionOption,
		cli.SubscribeFilterLogs,
	)
	if err != nil {
		log.Fatal("init ethereum contract client error", err)
	}
	err = contract.ExitNetwork(context.Background(), cli.Account)
	if err != nil {
		log.Fatal("exit network error", err)
	}
}

func cmd_run_func(cmd *cobra.Command, args []string) {
	cpath, _ := cmd.Flags().GetString("config")
	if cpath == "" {
		cpath, _ = cmd.Flags().GetString("c")
		if cpath == "" {
			logger.GetGlobalLogger().GetLogger(config.LOG_NODE).Error("empty config file path")
			log.Println("empty config file path")
			return
		}
	}

	if err := config.InitDefaultConfig(cpath); err != nil {
		log.Println("error", err)
		return
	}

	if err := config.BuildWorkSpace(); err != nil {
		log.Println("error", err)
		return
	}

	ctx := context.Background()
	conf := config.GetConfig()

	cacheModule := cache.NewCache(uint64(conf.CacheSize))
	cacheModule.RegisterSwapoutCallbacksCallbacks(func(i cache.Item) {
		if i.Value != "" {
			os.Remove(i.Value)
		}
	})
	//load cache records
	err := cacheModule.LoadCacheRecordsWithFiles(filepath.Join(conf.WorkSpace, config.DEFAULT_BUFFER_DIR))
	if err != nil {
		log.Println("new file buffer error", err)
		return
	}

	cli, err := chain.NewClient(
		chain.AccountPrivateKey(conf.SecretKey),
		chain.ChainID(conf.ChainId),
		chain.ConnectionRpcAddresss(conf.Rpcs),
		chain.EthereumGas(conf.GasFreeCap, conf.GasLimit),
	)
	if err != nil {
		log.Println("init ethereum client error", err)
		return
	}

	contract, err := chain.NewProtoContract(
		cli.GetEthClient(),
		conf.ProtoContract,
		cli.Account.Hex(),
		cli.NewTransactionOption,
		cli.SubscribeFilterLogs,
	)
	if err != nil {
		log.Println("init contract handle error", err)
		return
	}

	var selflessMode = true

	if conf.Token != "" && conf.TokenAcc != "" && conf.TokenAccSign != "" {
		selflessMode = false

		if info, err := contract.QueryRegisterInfo(cli.Account); err != nil {

			sign, err := hex.DecodeString(conf.TokenAccSign)
			if err != nil {
				log.Println("decode sign error", err)
				return
			}
			if err = contract.RegisterNode(context.Background(), chain.RegisterReq{
				NodeAcc:   cli.Account,
				TokenAcc:  common.HexToAddress(conf.TokenAcc),
				Endpoint:  conf.Endpoint,
				TokenId:   conf.Token,
				Signature: sign,
			}); err != nil {
				log.Println("register node on chain error", err)
				return
			}
		} else {
			log.Println("get registered node information:", info.TeeEth)
		}
	}

	fmg, err := manager.NewFileManager(conf.SecretKey, cacheModule, 10240, selflessMode)
	if err != nil {
		log.Println("new file manager error", err)
		return
	}

	// filepath.Walk(filepath.Join(conf.WorkSpace, config.DEFAULT_BUFFER_DIR),
	// 	func(path string, info fs.FileInfo, err error) error {
	// 		os.RemoveAll(path)
	// 		return nil
	// 	},
	// )

	mg, err := manager.NewProvideManager(
		cacheModule, fmg.GetTaskChannel(), contract,
		filepath.Join(conf.WorkSpace, config.DEFAULT_DB_DIR),
		filepath.Join(conf.WorkSpace, config.DEFAULT_BUFFER_DIR),
	)
	if err != nil {
		log.Println("new provide manager error", err)
		return
	}

	if err = mg.LoadStorageNodes(conf); err != nil {
		log.Println("load storage nodes error", err)
		return
	}

	ctx, stop := context.WithCancel(ctx)
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		<-signals
		log.Println("get system cancel signal.")
		stop()
		log.Println("wait for service to stop ...")
	}()
	go func() {
		if selflessMode {
			return
		}
		err = contract.ClaimWorkRewardServer(ctx, cli.Account)
		if err != nil {
			log.Println("run claim work reward server error", err)
			stop()
			return
		}
	}()

	go func() {
		err = mg.StorageTaskChecker(ctx)
		if err != nil {
			log.Println("storage status checker failed", err)
		}
	}()

	taskCh := make(chan *redis.Message, 10240)
	go func() {
		ticker := time.NewTicker(time.Minute * 15)
		for {
			if err = mg.LoadCdnNodes(conf); err != nil {
				log.Println("run subscribe task server error", err)
				time.Sleep(time.Minute)
				continue
			}
			if err := mg.SubscribeMessageFromCdnNodes(ctx, taskCh, client.CHANNEL_PROVIDE, client.CHANNEL_RETRIEVE); err != nil {
				log.Println("run subscribe task server error", err)
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		if err := fmg.RunTaskServer(ctx); err != nil {
			log.Println("run task server error", err)
			stop()
			return
		}
	}()
	go func() {
		if err := mg.UpdateStorageNodeStatus(ctx, conf); err != nil {
			log.Println("run update storage node server error", err)
			stop()
			return
		}
	}()
	logger.GetGlobalLogger().GetLogger(config.LOG_NODE).Info("🚀 CD2N Cacher is running ...")
	log.Println("🚀 CD2N Cacher cache service is running ...")
	err = mg.ExecuteTasks(ctx, taskCh)
	if err != nil {
		logger.GetGlobalLogger().GetLogger(config.LOG_NODE).Error("init ethereum client error", err)
		log.Println("execute tasks error", err)
		return
	}
	logger.GetGlobalLogger().GetLogger(config.LOG_NODE).Info("🔚 CD2N Cacher done.")
	log.Println("🔚 CD2N Cacher done.")
}
