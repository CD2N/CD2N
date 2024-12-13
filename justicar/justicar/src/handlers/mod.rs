pub(crate) mod internal_handler;
pub(crate) mod service_handler;
use crate::models::{CD2NState, RA};
use crate::utils::wallet::Wallet;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
pub struct AppError(StatusCode, anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, self.1.to_string()).into_response()
    }
}

pub fn return_error<E>(err: E, status_code: StatusCode) -> AppError
where
    E: Into<anyhow::Error>,
{
    AppError(status_code, err.into())
}
