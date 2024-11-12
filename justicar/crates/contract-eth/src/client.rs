use crate::error::ContractResult as Result;
use alloy::{
    hex::FromHex,
    primitives::Address,
    providers::{ProviderBuilder, WsConnect},
    sol,
};
use anyhow::{anyhow, Context};
use CDN::CDNInstance;
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    CDN,
    "abi/Cd2n.json"
);

pub(crate) type CDNContract = CDNInstance<
    alloy::pubsub::PubSubFrontend,
    alloy::providers::RootProvider<alloy::pubsub::PubSubFrontend>,
>;
#[derive(Clone)]
pub struct Contract {
    cdn: CDNContract,
}

impl Contract {
    pub async fn get_contract_conn(rpc_url: &str, contract_addr: String) -> Result<Self> {
        let ws = WsConnect::new(rpc_url);
        let provider = ProviderBuilder::new().on_ws(ws).await?;
        // let provider =
        //     ProviderBuilder::new().on_anvil_with_wallet_and_config(|anvil| anvil.fork(rpc_url));
        let cdn = CDN::new(
            Address::from_hex(contract_addr)
                .context("Invalid contract address parameter passing")?,
            provider,
        );
        Ok(Self { cdn })
    }

    pub async fn get_current_block_number(&self) -> Result<u64> {
        Ok(0)
    }

    pub async fn get_mrenclave_list(&self) -> Result<Vec<String>> {
        let mrenclave_list = self
            .cdn
            .getAllMREnclaveList()
            .call()
            .await
            .context("Get MrEnclaveList from contract failed")?
            ._0;

        Ok(mrenclave_list)
    }

    pub async fn get_mrsigner_list(&self) -> Result<Vec<String>> {
        let mrsigner_list = self
            .cdn
            .getAllMRSignerList()
            .call()
            .await
            .context("Get MRSignerList from contract failed")?
            ._0;

        Ok(mrsigner_list)
    }

    pub async fn get_update_block_number(&self) -> Result<Vec<u128>> {
        let update_block_number = self
            .cdn
            .getAllUpdateBlockNumber()
            .call()
            .await
            .context("Get UpdateBlockNumber vec from contract failed")?
            ._0;

        let mut update_block_number_list = Vec::new();
        for i in 0..update_block_number.len() {
            update_block_number_list.push(update_block_number[i].to::<u128>());
        }

        Ok(update_block_number_list)
    }
}
