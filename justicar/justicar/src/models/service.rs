use crate::utils::seal::Sealing;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
pub struct TestEcho {
    pub key: String,
    pub value: String,
    pub reward: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TestEchoResponse {}

//
#[derive(Serialize, Deserialize, Debug)]
pub struct UserReward {
    pub total_reward: u64,
    pub last_updated_block_number: u64,
}

//"cX...Xm": { "total_reward": 100, "last_updated": "15463" },
#[derive(Serialize, Deserialize, Debug)]
pub struct RewardDatabase {
    pub users: HashMap<String, UserReward>,
}

impl Sealing for RewardDatabase {
    fn seal_data(&self, path: impl AsRef<std::path::Path>) -> Result<(), anyhow::Error> {
        let seal_data_bytes = serde_json::to_vec(&self).unwrap();
        std::fs::write(&path, seal_data_bytes)?;
        Ok(())
    }

    fn unseal_data(&mut self, path: impl AsRef<std::path::Path>) -> Result<Vec<u8>, anyhow::Error> {
        let unseal_data = match std::fs::read(&path) {
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NotFound) => Ok(None),
            other => other.map(Some),
        }?;

        if unseal_data.is_some() {
            let reward_database: RewardDatabase =
                serde_json::from_slice(&unseal_data.clone().unwrap()).unwrap();
            self.users = reward_database.users;

            Ok(unseal_data.unwrap())
        } else {
            Ok(Vec::new())
        }
    }
}
