use crate::SgxError;
use anyhow::Result;
use rand::rngs::OsRng;
use ring::rand::SecureRandom;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub type EcdhSecretKey = EphemeralSecret;
pub type EcdhPublicKey = PublicKey;

pub fn gen_ecdh_key_pair() -> (EcdhSecretKey, EcdhPublicKey) {
    let ecdh_secret_key = EphemeralSecret::random_from_rng(OsRng);
    let ecdh_public_key = PublicKey::from(&ecdh_secret_key);

    return (ecdh_secret_key, ecdh_public_key);
}

pub(crate) fn generate_random_byte<const SIZE: usize>() -> [u8; SIZE] {
    let mut nonce_vec = [0u8; SIZE];
    let rand = ring::rand::SystemRandom::new();
    rand.fill(&mut nonce_vec).unwrap();
    nonce_vec
}
