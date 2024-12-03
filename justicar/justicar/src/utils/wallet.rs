use crate::models::Wallet;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::{Key, KeyInit};
use anyhow::{anyhow, Context, Result};
use bip39::{Language, Mnemonic};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

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

impl Wallet {
    pub fn ecdh_agreement(&self, other_public_key: [u8; 32]) -> Result<[u8; 32]> {
        let secret_data = secp256k1::ecdh::SharedSecret::new(
            &PublicKey::from_slice(&other_public_key).context("Invalid other's public key")?,
            &SecretKey::from_slice(&self.private_key).context("Invalid my secret key")?,
        );
        Ok(secret_data.secret_bytes())
    }

    pub fn decrypt_data_with_secret_and_nonce(
        &self,
        encrypted_data: &[u8],
        secret_data: [u8; 32],
        iv: &[u8; 12],
    ) -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&secret_data);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(iv);
        let plaintext = cipher.decrypt(nonce, encrypted_data).map_err(|e| {
            anyhow!(
                "Failed to decrypt data from provider because: {:?}",
                e.to_string()
            )
        })?;
        Ok(plaintext)
    }
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
