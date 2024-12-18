use crate::utils::seal::Sealing;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write};

#[derive(Clone, Serialize, Deserialize)]
pub struct SupplierDataAuditRequest {
    pub cid: String,
    pub user_acc: String,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub supplier_acc: String,
    pub data: Vec<u8>,
    pub request_id: String,
    pub user_sign: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SupplierDataAuditResponse {
    pub msg: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QueryInformationResponse {
    pub eth_address: String,
    pub secp256k1_public_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QueryDownloadCapacity {
    pub user_eth_address: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QueryDownloadCapacityResponse {
    pub user_eth_address: String,
    pub left_user_download_capacity: i32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestEcho {
    pub key: String,
    pub value: String,
    pub reward: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestEchoResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct SupplierReward {
    pub total_reward: u64,
    pub last_updated_block_number: u64,
}

//"user_acc":{"supplier_acc":{"total_reward":100,"last_updated":"15463"}...}
#[derive(Serialize, Deserialize, Debug)]
pub struct RewardDatabase {
    pub users_supplier_map: HashMap<String, HashMap<String, SupplierReward>>,
}
