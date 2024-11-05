#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Operation failed due to internal error")]
    InternalError,

    #[error("IO error occurred: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parse error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
}
