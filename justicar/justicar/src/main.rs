use anyhow::Result;
use eth::*;
use sgx_attestation::*;
use std::{sync::Arc, time::Duration};
mod handlers;
mod models;
mod routes;
mod utils;
use axum::{response::Html, routing::get, Router};
use clap::Parser;
use models::args::Args;

static CONTRACT_ADDRESS: &str = "769Ba37De24a264289F161efeAF5fd03Fe520C58";

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let cd2n_state = models::CD2NState::new(
        args.dev_mode,
        args.pccs_url,
        args.ra_timeout,
        args.chain_rpc,
        args.redis_url,
        CONTRACT_ADDRESS.to_string(),
    )
    .await?;
    // build our application with a route and state
    let app = routes::create_routes(cd2n_state).await;

    // run it
    let listener = tokio::net::TcpListener::bind("0.0.0.0:1309").await.unwrap();

    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
