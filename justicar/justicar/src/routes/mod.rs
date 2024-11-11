use std::sync::Arc;

use axum::Router;
mod internal_route;
use crate::models::CD2NState;

pub async fn create_routes(state: Arc<CD2NState>) -> Router {
    Router::new()
        .with_state(state)
        .merge(internal_route::handover_routes().await)
}
