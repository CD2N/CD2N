use crate::utils::wallet::generate_new_wallet;
use anyhow::Result;
use eth::client::Eth;
use handover::handover::HandoverHandler;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct Args {}

#[derive(Clone)]
pub struct CD2NState {
    pub handover_handler: Arc<Mutex<HandoverHandler>>,
    pub contract: Arc<Eth>,
    pub wallet: Arc<Mutex<Wallet>>,
}

pub struct RA;

#[derive(Clone, Serialize, Deserialize)]
pub struct Wallet {
    pub private_key: [u8; 32],
    pub public_key: Vec<u8>,
    pub mnemonic: String,
    pub eth_public_address: String,
}

impl CD2NState {
    pub async fn new(
        dev_mode: bool,
        pccs_url: String,
        ra_timeout: u64,
        rpc_url: String,
        contract_addr: String,
    ) -> Result<Self> {
        Ok(CD2NState {
            handover_handler: Arc::new(Mutex::new(HandoverHandler::new(
                dev_mode, pccs_url, ra_timeout,
            ))),
            contract: Arc::new(Eth::get_contract_conn(&rpc_url, contract_addr).await?),
            wallet: Arc::new(Mutex::new(generate_new_wallet()?)),
        })
    }
}
