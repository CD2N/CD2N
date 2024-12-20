use super::{service::RewardDatabase, CD2NState};
use crate::utils::{seal::Sealing, wallet::Wallet};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    pub wallet: Wallet,
    pub reward_database: RewardDatabase,
}

pub async fn secret_from_cdn_state(cdn: CD2NState) -> Result<Secret> {
    let reward_database: RewardDatabase =
        cdn.incentive_record_storage.lock().await.unseal_data()?;

    let wallet = cdn.wallet.clone();
    Ok(Secret {
        wallet,
        reward_database,
    })
}

pub async fn secret_to_cdn_state(secret: Secret, cdn: &mut CD2NState) -> Result<()> {
    cdn.incentive_record_storage
        .lock()
        .await
        .seal_data(&secret.reward_database)?;
    cdn.wallet = secret.wallet.clone();
    Ok(())
}
