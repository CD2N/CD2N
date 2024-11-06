use anyhow::{Ok, Result};
use contract_eth::*;
use sgx_attestation::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // let data = "Test Dcap".as_bytes();
    // let pccs_url = "https://dcap-sgp-dev.cess.cloud/sgx/certification/v4/";
    // let timeout = Duration::from_secs(10);
    // let att_report = match dcap::report::create_attestation_report(data, pccs_url, timeout) {
    //     Ok(r) => r,
    //     Err(e) => panic!("create report fail :{:?}", e.to_string()),
    // };

    // let (raw_quote, quote_collateral) = if let types::AttestationReport::SgxDcap {
    //     quote: raw_quote,
    //     collateral: c,
    // } = att_report
    // {
    //     let quote_collateral = match c.unwrap() {
    //         types::Collateral::SgxV30(quote_collateral) => quote_collateral,
    //     };
    //     (raw_quote, quote_collateral)
    // } else {
    //     panic!("not dcap attestation")
    // };

    // let now = chrono::Utc::now().timestamp() as u64;
    // let (report_data, tcb_hash, tcb_status, advisory_ids) =
    //     match dcap::verify(&raw_quote, &quote_collateral, now) {
    //         Ok(r) => (r.0, r.1, r.2, r.3),
    //         Err(e) => {
    //             panic!("fail to verify report :{:?}", e)
    //         }
    //     };
    // println!(
    //     "report data is :{:?}",
    //     String::from_utf8(report_data.to_vec())
    // );
    // println!("prime_data is :{:?}", hex::encode(tcb_hash));
    // println!("tcb_status is :{:?}", tcb_status);
    // println!("advisory_ids is :{:?}", advisory_ids);

    let contract = contract_eth::client::Contract::get_contract_conn(
        "wss://testnet-rpc.cess.cloud/ws/",
        "032f2F5c1f97269eB8EFd8fB2e3B612A559754dA".to_string(),
    )
    .await?;

    let mrenclave_list = contract.get_mrenclave_list().await?;
    println!("mrenclave_list is :{:?}", mrenclave_list);
    Ok(())
}
