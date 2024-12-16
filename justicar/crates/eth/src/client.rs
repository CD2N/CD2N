use crate::error::ContractResult as Result;
use alloy::{
    hex::FromHex,
    primitives::Address,
    providers::{Provider, ProviderBuilder, WsConnect},
    sol,
};
use anyhow::Context;
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
pub struct Eth {
    pub(crate) cdn_contract: Option<CDNContract>,
}

impl Eth {
    pub async fn get_contract_conn(rpc_url: &str, contract_addr: String) -> Result<Self> {
        let ws = WsConnect::new(rpc_url);
        let provider = ProviderBuilder::new().on_ws(ws).await?;
        // let provider =
        //     ProviderBuilder::new().on_anvil_with_wallet_and_config(|anvil| anvil.fork(rpc_url));
        let cdn_contract = Some(CDN::new(
            Address::from_hex(contract_addr)
                .context("Invalid contract address parameter passing")?,
            provider,
        ));
        Ok(Self { cdn_contract })
    }
}
