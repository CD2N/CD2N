use contract_eth::client::Contract;
use handover::handover::HandoverHandler;

pub struct Args {}

pub struct CD2NState {
    pub handover_handler: HandoverHandler,
    pub contract: Contract,
}

pub struct ContractClient {
    pub contract: Contract,
}

impl CD2NState {
    pub async fn new(
        dev_mode: bool,
        pccs_url: String,
        ra_timeout: u64,
        rpc_url: String,
        contract_addr: String,
    ) -> Self {
        CD2NState {
            handover_handler: HandoverHandler::new(dev_mode, pccs_url, ra_timeout),
            contract: Contract::get_contract_conn(&rpc_url, contract_addr)
                .await
                .unwrap(),
        }
    }
}
