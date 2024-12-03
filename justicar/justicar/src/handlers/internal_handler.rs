use super::*;
use anyhow::anyhow;
use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use eth::interact_contract::ContractInteract;
use handover::handover::{
    ExternalStatusGet, HandoverChallenge, HandoverChallengeResponse, HandoverSecretData,
    RemoteAttestation,
};
use sgx_attestation::{
    dcap::{self, report, Quote},
    types::{AttestationReport, Collateral},
};
use std::{collections::HashMap, time::Duration};

#[async_trait]
impl ExternalStatusGet for CD2NState {
    async fn get_block_number(&self) -> handover::HandoverResult<u64> {
        Ok(self
            .contract
            .get_current_block_number()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?)
    }

    async fn get_mrenclave_update_block_number_map(
        &self,
    ) -> handover::HandoverResult<HashMap<String, u128>> {
        let mrenclave_list = self
            .contract
            .get_mrenclave_list()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?;
        let update_block_number_list = self
            .contract
            .get_update_block_number()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?;
        let mut record_map = HashMap::new();
        for i in 0..mrenclave_list.len() {
            record_map.insert(mrenclave_list[i].clone(), update_block_number_list[i]);
        }

        Ok(record_map)
    }

    async fn get_mrsigner_list(&self) -> handover::HandoverResult<Vec<String>> {
        let mrsigner_list = self
            .contract
            .get_mrsigner_list()
            .await
            .map_err(|e| handover::SgxError::InternalError(e.to_string()))?;
        Ok(mrsigner_list)
    }
}

#[async_trait]
impl RemoteAttestation for RA {
    async fn create_remote_attestation_report(
        &self,
        payload: &[u8],
        pccs_url: &str,
        ra_timeout: Duration,
    ) -> handover::HandoverResult<Vec<u8>> {
        let att_report =
            dcap::report::create_attestation_report(payload, pccs_url, ra_timeout).await?;

        let report_vec = serde_json::to_vec(&att_report)?;
        Ok(report_vec)
    }

    ///Only verify the legitimacy of the report and do not make any business judgments.
    ///Of course, you can do so if you want.
    fn verify_remote_attestation_report(
        &self,
        payload: &[u8],
        attestation_report: Vec<u8>,
    ) -> handover::HandoverResult<(bool, String, String)> {
        let att_report: AttestationReport = serde_json::from_slice(&attestation_report)?;
        let (raw_quote, quote_collateral) = if let AttestationReport::SgxDcap {
            quote: raw_quote,
            collateral: c,
        } = att_report
        {
            let quote_collateral = match c.unwrap() {
                Collateral::SgxV30(quote_collateral) => quote_collateral,
            };
            (raw_quote, quote_collateral)
        } else {
            return Err(anyhow!("Attestation format not supported!").into());
        };
        let now = chrono::Utc::now().timestamp() as u64;
        let (
            report_data,
            _, /*todo:tcb hash limit?*/
            _, /*todo:tcb status limit?*/
            _, /*todo:advisory ids prohibition?*/
            mr_enclave,
            mr_signer,
        ) = dcap::verify(&raw_quote, &quote_collateral, now)
            .map_err(|e| anyhow!("failed to verify quote: {:?}", e))?;

        let mut pad_payload = [0u8; 64];
        pad_payload[..payload.len()].copy_from_slice(payload);

        let mr_enclave = hex::encode_upper(mr_enclave);
        let mr_signer = hex::encode_upper(mr_signer);

        if report_data != pad_payload {
            Ok((false, mr_enclave, mr_signer))
        } else {
            Ok((true, mr_enclave, mr_signer))
        }
    }
}

pub async fn generate_challenge(State(state): State<CD2NState>) -> impl IntoResponse {
    let challenge = state
        .handover_handler
        .clone()
        .lock()
        .await
        .generate_challenge(&state.clone())
        .await
        .unwrap();
    (StatusCode::OK, Json(challenge))
}

pub async fn handover_accept_challenge(
    State(state): State<CD2NState>,
    Json(params): Json<HandoverChallenge>,
) -> impl IntoResponse {
    let ra = RA {};
    let handover_challenge_response = state
        .handover_handler
        .clone()
        .lock()
        .await
        .handover_accept_challenge(params, &ra)
        .await
        .unwrap();

    (StatusCode::OK, Json(handover_challenge_response))
}

pub async fn handover_start(
    State(state): State<CD2NState>,
    Json(params): Json<HandoverChallengeResponse>,
) -> impl IntoResponse {
    let ra = RA {};
    let secret = state.wallet.clone().lock().await.to_owned();

    let secret_data = serde_json::to_vec(&secret).unwrap();
    let handover_secret_data = state
        .handover_handler
        .clone()
        .lock()
        .await
        .handover_start(secret_data, params, &ra, &state)
        .await
        .unwrap();

    (StatusCode::OK, Json(handover_secret_data))
}

pub async fn handover_receive(
    State(state): State<CD2NState>,
    Json(params): Json<HandoverSecretData>,
) -> impl IntoResponse {
    let ra = RA {};
    let handover_secret_data = state
        .handover_handler
        .clone()
        .lock()
        .await
        .handover_receive(params, &ra, &state)
        .await
        .unwrap();

    let wallet: Wallet = serde_json::from_slice(&handover_secret_data).unwrap();

    *state.wallet.clone().lock().await = wallet;
    StatusCode::OK
}
