use anyhow::Error;
use serde::Serialize;

pub trait Sealing {
    fn seal_data<Sealable: ?Sized + Serialize>(&mut self, data: &Sealable) -> Result<(), Error>;

    fn unseal_data<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, Error>;
}
