use crate::handlers::internal_handler;
use crate::models::CD2NState;
use axum::{
    routing::{get, post},
    Router,
};

pub async fn handover_routes(state: CD2NState) -> Router {
    Router::new().route(
        "/generate_challenge",
        get(internal_handler::generate_challenge)
            .post(internal_handler::handover_accept_challenge)
            .post(internal_handler::handover_start)
            .with_state(state),
    )
}

pub async fn status_routes() {
    //todo:
}
