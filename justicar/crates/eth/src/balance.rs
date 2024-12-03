use crate::client::Eth;
#[cfg(feature = "balance")]
use async_trait::async_trait;
#[async_trait]
trait Balance {
    async fn get_balance(&self) -> u128;
    async fn send_token() -> bool;
}

#[async_trait]
impl Balance for Eth {
    async fn get_balance(&self) -> u128 {
        //todo:

        0
    }
    async fn send_token() -> bool {
        //todo:

        true
    }
}
