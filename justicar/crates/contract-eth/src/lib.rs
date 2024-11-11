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
            "032f2F5c1f97269eB8EFd8fB2e3B612A559754dA".to_string(),
        )
        .await?;

        let mrenclave_list = contract.get_mrenclave_list().await?;
        println!("mrenclave_list is :{:?}", mrenclave_list);
        Ok(())
    }
}
