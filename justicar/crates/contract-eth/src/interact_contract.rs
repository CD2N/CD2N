pub trait EthereumContract {
    fn deploy(&self) -> Result<(), crate::error::ContractError>;
    fn call_method(
        &self,
        method_name: &str,
        params: &[String],
    ) -> Result<(), crate::error::ContractError>;
}

pub struct SampleContract {}

impl EthereumContract for SampleContract {
    fn deploy(&self) -> Result<(), crate::error::ContractError> {
        Ok(())
    }

    fn call_method(
        &self,
        method_name: &str,
        params: &[String],
    ) -> Result<(), crate::error::ContractError> {
        Ok(())
    }
}
