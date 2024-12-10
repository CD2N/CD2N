use anyhow::Error;
use std::path::Path;

pub const REWARD_RECORD_FILE: &str = "reward_record.seal";
pub trait Sealing {
    fn seal_data(&self, path: impl AsRef<Path>) -> Result<(), Error>;
    fn unseal_data(&mut self, path: impl AsRef<Path>) -> Result<Vec<u8>, Error>;
}
