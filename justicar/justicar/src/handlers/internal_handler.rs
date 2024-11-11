use crate::models::{CD2NState, ContractClient};
use anyhow::{anyhow, bail};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use handover::handover::{ExternalStatusGet, HandoverChallenge};
impl ExternalStatusGet for ContractClient {
    fn get_block_number(&self) -> handover::HandoverResult<u64> {
        return Err(anyhow!("a").into());
    }

    fn get_mrenclave_list(
        &self,
    ) -> handover::HandoverResult<std::collections::HashMap<String, u64>> {
        todo!()
    }

    fn get_mrsigner_list(&self) -> handover::HandoverResult<Vec<String>> {
        todo!()
    }
}

pub async fn generate_challenge() -> impl IntoResponse {
    // state.handover_handler.generate_challenge()
    (
        StatusCode::CREATED,
        Json(HandoverChallenge {
            sgx_target_info: Vec::new(),
            block_number: 32,
            dev_mode: true,
            nonce: [0u8; 32],
        }),
    )
}
