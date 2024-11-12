pub mod client;
pub mod error;
pub mod interact_contract;

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn test_async_add() -> Result<()> {
        let contract = crate::client::Contract::get_contract_conn(
            "ws://139.180.142.180:9944",
            "769Ba37De24a264289F161efeAF5fd03Fe520C58".to_string(),
        )
        .await?;

        let mrenclave_list = contract.get_mrenclave_list().await?;
        println!("mrenclave_list is :{:?}", mrenclave_list);
        Ok(())
    }
}
