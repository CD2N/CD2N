use super::*;

pub async fn service_routes(state: CD2NState) -> Router {
    Router::new()
        .route("/audit", post(service_handler::supplier_data_audit))
        .route("/echo", post(service_handler::test_echo))
        .with_state(state)
}
