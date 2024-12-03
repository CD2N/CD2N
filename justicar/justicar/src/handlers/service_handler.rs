use super::*;
use crate::models::service::{SupplierDataAuditRequest, SupplierDataAuditResponse};
use anyhow::anyhow;
use axum::{extract::State, http::StatusCode, Json};
use eth::interact_contract::ContractInteract;

pub async fn supplier_data_audit(
    State(state): State<CD2NState>,
    Json(params): Json<SupplierDataAuditRequest>,
) -> Result<Json<SupplierDataAuditResponse>, AppError> {
    let user_capacity = match state
        .redis_conn
        .lock()
        .await
        .get_data(&params.user_acc)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?
    {
        Some(data) => {
            //Get user download capacity from redis
            let num: i64 = data
                .parse()
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
            num
        }
        None => {
            //If this user is first time request,check the contract and set the download capacity
            let download_capacity = state
                .contract
                .get_user_download_capacity(
                    &state.wallet.lock().await.eth_public_address,
                    &params.user_acc,
                )
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

            state
                .redis_conn
                .lock()
                .await
                .set_data(&params.user_acc, &format!("{}", download_capacity))
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
            download_capacity
        }
    };

    //Try to decrypt the data with the shared secret
    let data_provider_secp256k1_pubkey = params.key;
    let shared_secret = state
        .wallet
        .lock()
        .await
        .ecdh_agreement(data_provider_secp256k1_pubkey.try_into().map_err(|_| {
            return_error(
                anyhow!("Invalid data provider public key,Please have a check"),
                StatusCode::BAD_REQUEST,
            )
        })?)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let data = state
        .wallet
        .lock()
        .await
        .decrypt_data_with_secret_and_nonce(
            &params.data,
            shared_secret,
            &params.nonce.try_into().map_err(|_| {
                return_error(
                    anyhow!("The length of nonce must be 12!"),
                    StatusCode::BAD_REQUEST,
                )
            })?,
        )
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    // Compute the data cid and compare it with the one in the request
    let data_cid = crate::utils::ipfs::compute_ipfs_cid_from_bytes(data.clone())
        .map_err(|e: anyhow::Error| return_error(e, StatusCode::BAD_REQUEST))?;

    if params.cid != data_cid {
        return Err(return_error(
            anyhow!("The decrypted data is not match the cid in the request!"),
            StatusCode::BAD_REQUEST,
        ));
    }

    let left_download_capacity = user_capacity - data.len() as i64;

    if left_download_capacity < 0 {
        return Err(return_error(
            anyhow!("The user's download capacity is not enough!"),
            StatusCode::FORBIDDEN,
        ));
    } else {
        // Update user download capacity in redis
        state
            .redis_conn
            .lock()
            .await
            .set_data(&params.user_acc, &format!("{}", left_download_capacity))
            .await
            .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
    };

    let response = SupplierDataAuditResponse {
        msg: String::from("success"),
        data,
    };

    Ok(Json(response))
}
