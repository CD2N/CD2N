pub(crate) mod args;
pub(crate) mod service;
use crate::utils::{
    bloom::Bloom,
    seal::Sealing,
    wallet::{generate_new_wallet, Wallet},
};
use anyhow::Result;
use db::client::RedisConn;
use eth::client::Eth;
use handover::handover::HandoverHandler;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::Arc,
};
use tokio::sync::Mutex;

pub const REWARD_RECORD_FILE: &str = "reward_record.seal";

#[derive(Clone)]
pub struct CD2NState {
    pub handover_handler: Arc<Mutex<HandoverHandler>>,
    pub contract: Arc<Eth>,
    pub redis_conn: Arc<Mutex<RedisConn>>,
    pub wallet: Wallet,
    pub bloom: Arc<Mutex<Bloom>>,
    pub incentive_record_storage: Arc<Mutex<IncentiveRecordStorage>>,
}

pub struct RA;

impl CD2NState {
    pub async fn new(
        dev_mode: bool,
        pccs_url: String,
        ra_timeout: u64,
        rpc_url: String,
        redis_url: String,
        safe_storage_path: String,
        contract_addr: String,
    ) -> Result<Self> {
        Ok(CD2NState {
            handover_handler: Arc::new(Mutex::new(HandoverHandler::new(
                dev_mode, pccs_url, ra_timeout,
            ))),
            contract: Arc::new(Eth::get_contract_conn(&rpc_url, contract_addr).await?),
            redis_conn: Arc::new(Mutex::new(RedisConn::create_connection(&redis_url).await?)),
            wallet: generate_new_wallet()?,
            bloom: Arc::new(Mutex::new(Bloom::create_bloom_filter(0.01, 100_000_000))),
            incentive_record_storage: Arc::new(Mutex::new(IncentiveRecordStorage(
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(std::path::Path::new(&safe_storage_path).join(REWARD_RECORD_FILE))?,
            ))),
        })
    }
}

pub struct IncentiveRecordStorage(File);
impl Sealing for IncentiveRecordStorage {
    fn seal_data<Sealable: ?Sized + serde::Serialize>(
        &mut self,
        seal_structure: &Sealable,
    ) -> std::result::Result<(), anyhow::Error> {
        self.0.set_len(0)?;
        self.0.seek(SeekFrom::Start(0))?;

        self.0.write_all(&serde_json::to_vec(seal_structure)?)?;

        Ok(())
    }

    fn unseal_data<T: serde::de::DeserializeOwned>(
        &mut self,
    ) -> std::result::Result<T, anyhow::Error> {
        self.0.flush()?;
        self.0.seek(std::io::SeekFrom::Start(0))?;

        let mut local_buffer = Vec::new();
        self.0.read_to_end(&mut local_buffer)?;
        if local_buffer.is_empty() {
            local_buffer = serde_json::to_vec(&service::RewardDatabase {
                users_supplier_map: HashMap::new(),
            })?;
        }

        Ok(serde_json::from_slice(&local_buffer)?)
    }
}
