use thiserror::Error;

#[derive(Debug, Error)]
pub enum WrappedError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Russh(#[from] russh::Error),

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
            WrappedError::Node(err) => err,
        }
    }
}
