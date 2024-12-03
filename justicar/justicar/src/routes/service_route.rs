use super::*;

pub async fn service_routes(state: CD2NState) -> Router {
    Router::new()
        .route("/", get(service_handler::supplier_data_audit))
        .with_state(state)
}
