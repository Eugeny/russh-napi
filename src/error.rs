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
    Node(#[from] napi::Error),
}

impl From<WrappedError> for napi::Error {
    fn from(value: WrappedError) -> Self {
        match value {
            WrappedError::Io(err) => {
                napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
            }
            WrappedError::Russh(err) => {
                napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
            }
            WrappedError::RusshKeys(err) => {
                napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
            }
            WrappedError::AgentAuthError(err) => {
                napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
            }
            WrappedError::Sftp(err) => {
                napi::Error::new(napi::Status::GenericFailure, format!("{err:?}"))
            }
            WrappedError::Node(err) => err,
        }
    }
}
