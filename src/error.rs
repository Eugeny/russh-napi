use russh::AgentAuthError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WrappedError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Russh(#[from] russh::Error),

    #[error(transparent)]
    RusshKeys(#[from] russh_keys::Error),

    #[error(transparent)]
    AgentAuthError(#[from] AgentAuthError),

    #[error(transparent)]
    Sftp(#[from] russh_sftp::client::error::Error),

    #[error(transparent)]
    Socks(#[from] tokio_socks::Error),

    #[error(transparent)]
    Http(#[from] async_http_proxy::HttpError),

    #[error(transparent)]
    Node(#[from] napi::Error),
}

fn to_napi_err<E: std::fmt::Debug>(err: E) -> napi::Error {
    napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
}

impl From<WrappedError> for napi::Error {
    fn from(value: WrappedError) -> Self {
        match value {
            WrappedError::Io(err) => to_napi_err(err),
            WrappedError::Russh(err) => to_napi_err(err),
            WrappedError::RusshKeys(err) => to_napi_err(err),
            WrappedError::AgentAuthError(err) => to_napi_err(err),
            WrappedError::Sftp(err) => to_napi_err(err),
            WrappedError::Socks(err) => to_napi_err(err),
            WrappedError::Http(err) => to_napi_err(err),
            WrappedError::Node(err) => err,
        }
    }
}
