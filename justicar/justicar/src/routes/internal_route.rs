use crate::handlers::internal_handler;
use axum::{
    routing::{get, post},
    Router,
};

pub async fn handover_routes() -> Router {
    Router::new().route(
        "/generate_challenge",
        get(internal_handler::generate_challenge),
    )
}

pub async fn status_routes() {
    //todo:
}
