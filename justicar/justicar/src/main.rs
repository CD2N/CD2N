use anyhow::Result;
use contract_eth::*;
use sgx_attestation::*;
use std::{sync::Arc, time::Duration};
mod handlers;
mod models;
mod routes;
use axum::{response::Html, routing::get, Router};

#[tokio::main]
async fn main() -> Result<()> {
    let cd2n_state = Arc::new(
        models::CD2NState::new(true, "".to_string(), 32, "".to_string(), "".to_string()).await,
    );
    // build our application with a route and state
    let app = routes::create_routes(cd2n_state).await;

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();

    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
