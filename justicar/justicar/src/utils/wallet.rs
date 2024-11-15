use crate::models::Wallet;
use anyhow::{Context, Result};
use bip39::{Language, Mnemonic};
use secp256k1::{Secp256k1, SecretKey};

use alloy::signers::local::{coins_bip39::English, MnemonicBuilder};
pub fn generate_new_wallet() -> Result<Wallet> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();

    let mnemonic_phrase = mnemonic.to_string();

    let wallet = MnemonicBuilder::<English>::default()
        .phrase(mnemonic_phrase.clone())
        .index(0)?
        .password("")
        .build()?;

    let private_key: [u8; 32] = wallet.to_bytes().0;

    let secp = Secp256k1::new();
    let public_key = SecretKey::from_slice(&private_key)
        .context("Invalid secret key size")?
        .public_key(&secp);

    Ok(Wallet {
        private_key: private_key,
        public_key: public_key.serialize().to_vec(),
        mnemonic: mnemonic_phrase,
        eth_public_address: wallet.address().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_new_wallet() -> Result<()> {
        let rand_wallet = generate_new_wallet()?;

        println!("Private Key: {:#?}", hex::encode(rand_wallet.private_key));
        println!("Public Key: {:#?}", hex::encode(rand_wallet.public_key));
        println!("Mnemonic: {:?}", rand_wallet.mnemonic);
        println!("Eth Public Address: {}", rand_wallet.eth_public_address);
        Ok(())
    }
}
