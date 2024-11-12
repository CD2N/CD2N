use std::sync::Arc;

use contract_eth::client::Contract;
use handover::handover::HandoverHandler;
use tokio::sync::Mutex;

pub struct Args {}

#[derive(Clone)]
pub struct CD2NState {
    pub handover_handler: Arc<Mutex<HandoverHandler>>,
    pub contract: Arc<Contract>,
    pub wallet_sk: Vec<u8>,
}

pub struct RA;

impl CD2NState {
    pub async fn new(
        dev_mode: bool,
        pccs_url: String,
        ra_timeout: u64,
        rpc_url: String,
        contract_addr: String,
    ) -> Self {
        CD2NState {
            handover_handler: Arc::new(Mutex::new(HandoverHandler::new(
                dev_mode, pccs_url, ra_timeout,
            ))),
            contract: Arc::new(
                Contract::get_contract_conn(&rpc_url, contract_addr)
                    .await
                    .unwrap(),
            ),
            wallet_sk: [6_u8; 32].to_vec(),
        }
    }
}
