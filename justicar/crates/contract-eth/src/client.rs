use alloy::{
    hex::FromHex,
    primitives::Address,
    providers::{ProviderBuilder, WsConnect},
    sol,
};
use anyhow::Result;
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
pub struct Contract {
    cdn: CDNContract,
}

impl Contract {
    pub async fn get_contract_conn(rpc_url: &str, contract_addr: String) -> Result<Self> {
        let ws = WsConnect::new(rpc_url);
        let provider = ProviderBuilder::new().on_ws(ws).await?;
        // let provider =
        //     ProviderBuilder::new().on_anvil_with_wallet_and_config(|anvil| anvil.fork(rpc_url));
        let cdn = CDN::new(Address::from_hex(contract_addr)?, provider);
        Ok(Self { cdn })
    }

    pub async fn get_mrenclave_list(&self) -> Result<Vec<String>> {
        let mrenclave_list = self.cdn.getAllMREnclaveList().call().await?._0;

        Ok(mrenclave_list)
    }
}
