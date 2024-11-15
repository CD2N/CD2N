#[cfg(feature = "contract-interact")]
use crate::client::Eth;
use crate::error::ContractResult as Result;
use alloy::providers::Provider;
use anyhow::{anyhow, Context};
use async_trait::async_trait;

#[cfg(feature = "contract-interact")]
#[async_trait]
pub trait ContractInteract {
    async fn get_current_block_number(&self) -> Result<u64>;
    async fn get_mrenclave_list(&self) -> Result<Vec<String>>;
    async fn get_mrsigner_list(&self) -> Result<Vec<String>>;
    async fn get_update_block_number(&self) -> Result<Vec<u128>>;
}

#[cfg(feature = "contract-interact")]
#[async_trait]
impl ContractInteract for Eth {
    async fn get_current_block_number(&self) -> Result<u64> {
        Ok(self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("get_current_block_number failed: Please init cdn_contract first!")
            })?
            .provider()
            .get_block_number()
            .await
            .context("Get block chain current block number failed")?)
    }
    async fn get_mrenclave_list(&self) -> Result<Vec<String>> {
        Ok(self
            .cdn_contract
            .clone()
            .ok_or_else(|| anyhow!("get_mrenclave_list failed: Please init cdn_contract first!"))?
            .getAllMREnclaveList()
            .call()
            .await
            .context("Get MrEnclaveList from contract failed")?
            ._0)
    }
    async fn get_mrsigner_list(&self) -> Result<Vec<String>> {
        Ok(self
            .cdn_contract
            .clone()
            .ok_or_else(|| anyhow!("get_mrsigner_list failed: Please init cdn_contract first!"))?
            .getAllMRSignerList()
            .call()
            .await
            .context("Get MRSignerList from contract failed")?
            ._0)
    }
    async fn get_update_block_number(&self) -> Result<Vec<u128>> {
        let update_block_number = self
            .cdn_contract
            .clone()
            .ok_or_else(|| {
                anyhow!("get_update_block_number failed: Please init cdn_contract first!")
            })?
            .getAllUpdateBlockNumber()
            .call()
            .await
            .context("Get UpdateBlockNumber vec from contract failed")?
            ._0;

        let mut update_block_number_list = Vec::new();
        for i in 0..update_block_number.len() {
            update_block_number_list.push(update_block_number[i].to::<u128>());
        }

        Ok(update_block_number_list)
    }
}
