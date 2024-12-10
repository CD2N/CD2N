use super::*;
use crate::{
    models::service::{
        RewardDatabase, SupplierDataAuditRequest, SupplierDataAuditResponse, TestEcho,
        TestEchoResponse, UserReward,
    },
    utils::seal::{Sealing, REWARD_RECORD_FILE},
};
use anyhow::anyhow;
use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    Json,
};
use eth::interact_contract::ContractInteract;
use std::{collections::HashMap, vec};

pub async fn supplier_data_audit(
    State(state): State<CD2NState>,
    mut multipart: Multipart,
) -> Result<Json<SupplierDataAuditResponse>, AppError> {
    let mut file_data = Vec::new();
    let mut cid = String::new();
    let mut user_acc = String::new();
    let mut key = Vec::new();
    let mut nonce = Vec::new();
    let mut supplier_acc = String::new();
    let mut request_id = String::new();
    let mut user_sign = Vec::new();

    while let Some(field) = multipart.next_field().await.unwrap() {
        if let Some(name) = field.name() {
            println!("name is :{:?}", name);
            match name {
                "file" => {
                    file_data = field
                        .bytes()
                        .await
                        .map_err(|e| {
                            return_error(
                                anyhow!("The input file is incorrect:{:?}", e.to_string()),
                                StatusCode::BAD_REQUEST,
                            )
                        })?
                        .to_vec();
                }
                "cid" => {
                    cid = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input cid is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "user_acc" => {
                    user_acc = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input user_acc is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "key" => {
                    key = serde_json::from_slice::<Vec<u8>>(
                        &field
                            .bytes()
                            .await
                            .map_err(|e| {
                                return_error(
                                    anyhow!("The input key is incorrect:{:?}", e.to_string()),
                                    StatusCode::BAD_REQUEST,
                                )
                            })?
                            .to_vec(),
                    )
                    .map_err(|e| {
                        return_error(
                            anyhow!("Error when parsing key:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "nonce" => {
                    nonce = serde_json::from_slice::<Vec<u8>>(
                        &field
                            .bytes()
                            .await
                            .map_err(|e| {
                                return_error(
                                    anyhow!("The input nonce is incorrect:{:?}", e.to_string()),
                                    StatusCode::BAD_REQUEST,
                                )
                            })?
                            .to_vec(),
                    )
                    .map_err(|e| {
                        return_error(
                            anyhow!("Error when parsing nonce:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "supplier_acc" => {
                    supplier_acc = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input supplier_acc is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "request_id" => {
                    request_id = field.text().await.map_err(|e| {
                        return_error(
                            anyhow!("The input request_id is incorrect:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                "user_sign" => {
                    user_sign = serde_json::from_slice::<Vec<u8>>(
                        &field
                            .bytes()
                            .await
                            .map_err(|e| {
                                return_error(
                                    anyhow!("The input user_sign is incorrect:{:?}", e.to_string()),
                                    StatusCode::BAD_REQUEST,
                                )
                            })?
                            .to_vec(),
                    )
                    .map_err(|e| {
                        return_error(
                            anyhow!("Error when parsing user_sign:{:?}", e.to_string()),
                            StatusCode::BAD_REQUEST,
                        )
                    })?;
                }
                other => {
                    return Err(return_error(
                        anyhow!(
                            "Unable to identify, please do not pass in useless fields:{:?}",
                            other
                        ),
                        StatusCode::BAD_REQUEST,
                    ));
                }
            }
        }
    }

    //Check the request is from the user indeed.
    let user_walllet_pbk = crate::utils::wallet::restore_public_key_from_golang_signature(
        user_sign.clone().try_into().map_err(|_| {
            return_error(
                anyhow!("The length of user_sign must be 65"),
                StatusCode::BAD_REQUEST,
            )
        })?,
        request_id.clone().as_bytes(),
    )
    .map_err(|e| return_error(e, StatusCode::BAD_REQUEST))?;

    if !crate::utils::wallet::convert_public_key_to_eth_address(user_walllet_pbk)
        .map_err(|e| return_error(e, StatusCode::BAD_REQUEST))?
        .eq(&user_acc.clone().to_uppercase())
    {
        return Err(return_error(
            anyhow!("The user_sign is not from the user :{:?}", user_acc.clone()),
            StatusCode::BAD_REQUEST,
        ));
    }

    let mut redis_guard = state.redis_conn.lock().await;

    //Get user download capacity from redis or contract
    let user_capacity = match redis_guard
        .get_data(&user_acc)
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
                .get_user_order(&state.wallet.lock().await.eth_public_address, &user_acc)
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

            redis_guard
                .set_data(&user_acc, &format!("{}", download_capacity))
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
            download_capacity
        }
    };

    //Set the request into bloom filter. Preventing duplicate requests.
    if state
        .bloom
        .clone()
        .lock()
        .await
        .check_value(request_id.clone())
    {
        return Err(return_error(
            anyhow!("This request:{:?} has been submitted before!", request_id),
            StatusCode::BAD_REQUEST,
        ));
    };
    state
        .bloom
        .clone()
        .lock()
        .await
        .insert_value(request_id.clone());

    //Try to decrypt the data with the shared secret
    let data_provider_secp256k1_pubkey = key;
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
        .decrypt_data_with_shared_secret_and_nonce(
            &file_data,
            shared_secret,
            &nonce.try_into().map_err(|_| {
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

    if cid != data_cid {
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
        redis_guard
            .set_data(&user_acc, &format!("{}", left_download_capacity))
            .await
            .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;
    };

    // Update the reward record in safe storage file.
    let safe_storage_path_guard = state.safe_storage_path.lock().await;
    let path = std::path::Path::new(&safe_storage_path_guard.clone()).join(REWARD_RECORD_FILE);
    let mut previous_seal_data = RewardDatabase {
        users: HashMap::new(),
    };
    previous_seal_data
        .unseal_data(&path)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let record = previous_seal_data.users.get(&user_acc);
    let new_reward = if let Some(record) = record {
        UserReward {
            total_reward: data.len() as u64 + record.total_reward,
            last_updated_block_number: state
                .contract
                .get_current_block_number()
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?,
        }
    } else {
        UserReward {
            total_reward: data.len() as u64,
            last_updated_block_number: state
                .contract
                .get_current_block_number()
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?,
        }
    };
    previous_seal_data
        .users
        .insert(user_acc.clone(), new_reward);

    println!(
        "save reward record:{:?}",
        previous_seal_data.users.get(&user_acc)
    );

    previous_seal_data
        .seal_data(path)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let response = SupplierDataAuditResponse {
        msg: String::from("success"),
        data,
    };

    Ok(Json(response))
}

pub async fn test_echo(
    State(state): State<CD2NState>,
    Json(params): Json<TestEcho>,
) -> Result<Json<TestEchoResponse>, AppError> {
    //test redis conn
    let mut redis_guard = state.redis_conn.lock().await;

    redis_guard
        .set_data(&params.key, &params.value)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    println!("{:?}", params.key.clone());
    println!("{:?}", params.value.clone());

    let result = redis_guard
        .get_data(&params.key)
        .await
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    println!("{:?}", result);

    //test tee storage data
    let user = params.key;

    let safe_storage_path_guard = state.safe_storage_path.lock().await;

    let path = std::path::Path::new(&safe_storage_path_guard.clone()).join(REWARD_RECORD_FILE);
    let mut previous_seal_data = RewardDatabase {
        users: HashMap::new(),
    };
    previous_seal_data
        .unseal_data(&path)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let record = previous_seal_data.users.get(&user);
    let new_reward = if let Some(record) = record {
        UserReward {
            total_reward: params.reward + record.total_reward,
            last_updated_block_number: state
                .contract
                .get_current_block_number()
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?,
        }
    } else {
        UserReward {
            total_reward: params.reward,
            last_updated_block_number: state
                .contract
                .get_current_block_number()
                .await
                .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?,
        }
    };
    previous_seal_data.users.insert(user.clone(), new_reward);

    println!("------------{:?}", previous_seal_data.users.get(&user));

    previous_seal_data
        .seal_data(path)
        .map_err(|e| return_error(e, StatusCode::INTERNAL_SERVER_ERROR))?;

    let response = TestEchoResponse {};
    Ok(Json(response))
}
