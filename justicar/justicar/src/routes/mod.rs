mod internal_route;
mod service_route;
use crate::handlers::{internal_handler, service_handler};
use crate::models::CD2NState;
use axum::{
    routing::{get, post},
    Router,
};

pub async fn create_routes(state: CD2NState) -> Router {
    Router::new()
        .merge(service_route::service_routes(state.clone()).await)
        .merge(internal_route::handover_routes(state.clone()).await)
}
