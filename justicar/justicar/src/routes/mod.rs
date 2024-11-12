use std::sync::Arc;

use axum::Router;
mod internal_route;
use crate::models::CD2NState;

pub async fn create_routes(state: CD2NState) -> Router {
    Router::new().merge(internal_route::handover_routes(state.clone()).await)
}
