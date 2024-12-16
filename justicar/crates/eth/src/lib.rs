pub mod balance;
pub mod client;
pub mod error;
pub mod interact_contract;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use interact_contract::ContractInteract;

    #[tokio::test]
    async fn test_contract_conn() -> Result<()> {
        let contract = crate::client::Eth::get_contract_conn(
            "ws://139.180.142.180:9944",
            "ce078A9098dF68189Cbe7A42FC629A4bDCe7dDD4".to_string(),
        )
        .await?;

        let mrenclave_list = contract.get_mrenclave_list().await?;
        println!("mrenclave_list is :{:?}", mrenclave_list);
        Ok(())
    }

    #[tokio::test]
    async fn test_get_user_total_traffic() -> Result<()> {
        let contract = crate::client::Eth::get_contract_conn(
            "ws://139.180.142.180:9944",
            "ce078A9098dF68189Cbe7A42FC629A4bDCe7dDD4".to_string(),
        )
        .await?;

        let user_total_traffic = contract
            .get_user_total_traffic(
                "0x4826E8ac5159B73bbe784F2c8b1EF1193b6e6Be6",
                "8aDc35e1a9a5A6217a63998821D3c413b2d4719B",
            )
            .await?;
        println!("user_total_traffic is :{:?}", user_total_traffic);
        Ok(())
    }
}
