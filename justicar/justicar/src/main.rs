use anyhow::Result;
use eth::*;
use sgx_attestation::*;
use std::{sync::Arc, time::Duration};
mod handlers;
mod models;
mod routes;
mod utils;
use axum::{response::Html, routing::get, Router};

#[tokio::main]
async fn main() -> Result<()> {
    let cd2n_state = models::CD2NState::new(
        false,
        "https://dcap-sgp-dev.cess.cloud/sgx/certification/v4/".to_string(),
        300,
        "ws://139.180.142.180:9944".to_string(),
        "769Ba37De24a264289F161efeAF5fd03Fe520C58".to_string(),
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
