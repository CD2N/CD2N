use std::time::Duration;

use crate::{utils, SgxError};
use anyhow::Result;
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub struct HandoverHandler {
    ecdh_secret_key: Option<utils::EcdhSecretKey>,
    echd_public_key: Option<utils::EcdhPublicKey>,
    /// The last challenge create by this justicar
    handover_last_challenge: Option<HandoverChallenge>,

    /// The following content can be configue
    pub pccs_url: String,
    pub ra_timeout: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandoverChallenge {
    pub sgx_target_info: Vec<u8>,
    // pub block_number: BlockNumber,
    // pub now: u64,
    pub dev_mode: bool,
    pub nonce: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChallengeHandlerInfo {
    pub challenge: HandoverChallenge,
    pub sgx_local_report: Vec<u8>,
    pub ecdh_pubkey: [u8; 32],
}

impl HandoverHandler {
    /// [old]1st get challenge from old
    fn generate_challenge(dev_mode: bool) -> HandoverChallenge {
        let sgx_target_info = if dev_mode {
            vec![]
        } else {
            let my_target_info = crate::target_info().unwrap();
            crate::encode(&my_target_info).to_vec()
        };
        let challenge = HandoverChallenge {
            sgx_target_info,
            dev_mode: dev_mode,
            nonce: crate::utils::generate_random_byte::<32>(),
        };
        challenge
    }

    ///[this]
    async fn handover_accept_challenge(
        &mut self,
        challenge: HandoverChallenge,
        ra: &impl RemoteAttestation,
    ) -> Result<pb::HandoverChallengeResponse> {
        // do the secret exchange safely by using ECDH key exchange
        let (ecdh_secret_key, echd_public_key) = utils::gen_ecdh_key_pair();
        let dev_mode = challenge.dev_mode;
        self.ecdh_secret_key = Some(ecdh_secret_key);
        self.echd_public_key = Some(echd_public_key);

        // generate local attestation report to ensure the two justicar on same instance
        let sgx_local_report = if !dev_mode {
            let its_target_info = unsafe { crate::decode(&challenge.sgx_target_info)? };
            // the report data does not matter since we only care about the origin
            let report = crate::report(its_target_info, &[0; 64])?;
            crate::encode(&report).to_vec()
        } else {
            info!("create local attestation report in dev mode");
            vec![]
        };

        // generate remote attestation report,make the old justicar trust that the secret exchange with this one is credible
        let challenge_handler = ChallengeHandlerInfo {
            challenge,
            sgx_local_report,
            ecdh_pubkey: echd_public_key.to_bytes(),
        };

        let mut hasher = Sha256::new();
        hasher.update(
            serde_json::to_vec(&challenge_handler)
                .map_err(|e| SgxError::SerdeError(e.to_string()))?,
        );

        let handler_hash: [u8; 32] = hasher.finalize().into();

        let attestation = Some(ra.create_attestation_report(
            handler_hash,
            self.pccs_url,
            Duration::from_secs(self.ra_timeout),
        ));
        let attestation = if !dev_mode {
            Some(create_attestation_report_on(
                &handler_hash,
                cestory.args.ra_timeout,
                cestory.args.ra_max_retries,
            )?)
        } else {
            info!("Omit client RA report for dev mode challenge");
            None
        };

        Ok(Response::new(pb::HandoverChallengeResponse::new(
            challenge_handler,
            attestation,
        )))
    }

    /// [old]Key Handover Server: Get worker key with RA report on challenge from another Ceseal
    async fn handover_start(
        &self,
        request: Request<pb::HandoverChallengeResponse>,
    ) -> RpcResult<pb::HandoverWorkerKey> {
        let request = request.into_inner();
        let mut cestory = self.lock_ceseal(false, true)?;
        let attestation_provider = cestory.attestation_provider;
        let dev_mode = cestory.dev_mode;
        let in_sgx = attestation_provider == Some(AttestationProvider::Ias)
            || attestation_provider == Some(AttestationProvider::Dcap);
        let (block_number, now_ms) = cestory.current_block()?;

        // 1. verify client RA report to ensure it's in sgx
        // this also ensure the message integrity
        let challenge_handler = request.decode_challenge_handler().map_err(from_display)?;
        let block_sec = now_ms / 1000;
        let attestation = if !dev_mode && in_sgx {
            let payload_hash = sp_core::hashing::blake2_256(&challenge_handler.encode());
            let raw_attestation = request
                .attestation
                .ok_or_else(|| from_display("Client attestation not found"))?;
            let attn_to_validate =
                Option::<AttestationReport>::decode(&mut &raw_attestation.encoded_report[..])
                    .map_err(|_| from_display("Decode client attestation failed"))?;
            // The time from attestation report is generated by IAS, thus trusted. By default, it's valid for **10h**.
            // By ensuring our system timestamp is within the valid period, we know that this ceseal is not hold back by
            // malicious workers.
            validate_attestation_report(
                attn_to_validate.clone(),
                &payload_hash,
                block_sec,
                false,
                vec![],
                false,
            )
            .map_err(|_| from_display("Invalid client RA report"))?;
            attn_to_validate
        } else {
            info!("Skip client RA report check in dev mode");
            None
        };
        // 2. verify challenge validity to prevent replay attack
        let challenge = challenge_handler.challenge;
        if !cestory.verify_worker_key_challenge(&challenge) {
            return Err(Status::invalid_argument("Invalid challenge"));
        }
        // 3. verify sgx local attestation report to ensure the handover ceseals are on the same machine
        if !dev_mode && in_sgx {
            let recv_local_report = unsafe {
                sgx_api_lite::decode(&challenge_handler.sgx_local_report)
                    .map_err(|_| from_display("Invalid client LA report"))?
            };
            sgx_api_lite::verify(recv_local_report)
                .map_err(|_| from_display("No remote handover"))?;
        } else {
            info!("Skip client LA report check in dev mode");
        }
        // 4. verify challenge block height and report timestamp
        // only challenge within 150 blocks (30 minutes) is accepted
        let challenge_height = challenge.block_number;
        if !(challenge_height <= block_number && block_number - challenge_height <= 150) {
            return Err(Status::invalid_argument("Outdated challenge"));
        }
        // 5. verify ceseal launch date, never handover to old ceseal
        if !dev_mode && in_sgx {
            let my_la_report = {
                // target_info and reportdata not important, we just need the report metadata
                let target_info =
                    sgx_api_lite::target_info().expect("should not fail in SGX; qed.");
                sgx_api_lite::report(&target_info, &[0; 64])
                    .map_err(|_| from_display("Cannot read server ceseal info"))?
            };
            let my_runtime_hash = {
                let sgx_fields = SgxFields {
                    mr_enclave: my_la_report.body.mr_enclave.m,
                    mr_signer: my_la_report.body.mr_signer.m,
                    isv_prod_id: my_la_report.body.isv_prod_id.to_ne_bytes(),
                    isv_svn: my_la_report.body.isv_svn.to_ne_bytes(),
                    report_data: [0; 64],
                    confidence_level: 0,
                };
                sgx_fields.measurement_hash()
            };
            let runtime_state = cestory.runtime_state()?;
            let my_runtime_timestamp = runtime_state
                .chain_storage
                .read()
                .get_ceseal_bin_added_at(&my_runtime_hash)
                .ok_or_else(|| from_display("Server ceseal not allowed on chain"))?;

            let attestation =
                attestation.ok_or_else(|| from_display("Client attestation not found"))?;
            let runtime_hash = match attestation {
                AttestationReport::SgxIas {
                    ra_report,
                    signature: _,
                    raw_signing_cert: _,
                } => {
                    let (sgx_fields, _) = SgxFields::from_ias_report(&ra_report)
                        .map_err(|_| from_display("Invalid client RA report"))?;
                    sgx_fields.measurement_hash()
                }
                AttestationReport::SgxDcap {
                    quote,
                    collateral: _,
                } => {
                    let (sgx_fields, _) = SgxFields::from_dcap_quote_report(&quote)
                        .map_err(|_| from_display("Invalid client RA report"))?;
                    sgx_fields.measurement_hash()
                }
            };
            let req_runtime_timestamp = runtime_state
                .chain_storage
                .read()
                .get_ceseal_bin_added_at(&runtime_hash)
                .ok_or_else(|| from_display("Client ceseal not allowed on chain"))?;

            if my_runtime_timestamp >= req_runtime_timestamp {
                return Err(Status::internal(
                    "Same ceseal version or rollback ,No local handover provided",
                ));
            }
        } else {
            info!("Skip ceseal timestamp check in dev mode");
        }

        // Share the key with attestation
        let ecdh_pubkey = challenge_handler.ecdh_pubkey;
        let iv = crate::generate_random_iv();
        let runtime_data = cestory.persistent_runtime_data().map_err(from_display)?;
        let (my_identity_key, _) = runtime_data.decode_keys();
        let (ecdh_pubkey, encrypted_key) = key_share::encrypt_secret_to(
            &my_identity_key,
            &[b"worker_key_handover"],
            &ecdh_pubkey.0,
            &SecretKey::Sr25519(runtime_data.sk),
            &iv,
        )
        .map_err(from_debug)?;
        let encrypted_key = EncryptedKey {
            ecdh_pubkey: sr25519::Public::from_raw(ecdh_pubkey),
            encrypted_key,
            iv,
        };
        let runtime_state = cestory.runtime_state()?;
        let genesis_block_hash = runtime_state.genesis_block_hash;
        let encrypted_worker_key = EncryptedWorkerKey {
            genesis_block_hash,
            dev_mode,
            encrypted_key,
        };

        let worker_key_hash = sp_core::hashing::blake2_256(&encrypted_worker_key.encode());
        let attestation = if !dev_mode && in_sgx {
            Some(create_attestation_report_on(
                &cestory.platform,
                attestation_provider,
                &worker_key_hash,
                cestory.args.ra_timeout,
                cestory.args.ra_max_retries,
            )?)
        } else {
            info!("Omit RA report in workerkey response in dev mode");
            None
        };

        Ok(Response::new(pb::HandoverWorkerKey::new(
            encrypted_worker_key,
            attestation,
        )))
    }
}

pub trait RemoteAttestation {
    fn create_attestation_report(
        &self,
        payload: Vec<u8>,
        pccs_url: String,
        ra_timeout: Duration,
    ) -> Vec<u8>;
    fn verify_attestation_report(&self) -> bool;
}
