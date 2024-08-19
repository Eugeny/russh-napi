use crate::error::WrappedError;
use napi::bindgen_prelude::Uint8Array;
use napi::Result;
use napi_derive::napi;
use russh_keys::PublicKeyBase64;

#[napi]
#[derive(Clone)]
pub struct SshPublicKey {
    inner: russh_keys::key::PublicKey,
}

#[napi]
impl SshPublicKey {
    #[napi]
    pub fn algorithm(&self) -> String {
        self.inner.name().into()
    }

    #[napi]
    pub fn fingerprint(&self) -> String {
        self.inner.fingerprint()
    }

    #[napi]
    pub fn base64(&self) -> String {
        self.inner.public_key_base64()
    }

    #[napi]
    pub fn bytes(&self) -> Uint8Array {
        self.inner.public_key_bytes().into()
    }
}

impl From<russh_keys::key::PublicKey> for SshPublicKey {
    fn from(inner: russh_keys::key::PublicKey) -> Self {
        SshPublicKey { inner }
    }
}

#[napi]
#[derive(Clone)]
pub struct SshKeyPair {
    pub(crate) inner: russh_keys::key::KeyPair,
}

#[napi]
impl SshKeyPair {
    #[napi]
    pub fn public_key(&self) -> Result<SshPublicKey> {
        self.inner
            .clone_public_key()
            .map_err(|e| WrappedError::from(russh::Error::from(e)).into())
            .map(Into::into)
    }
}

#[napi]
pub fn parse_key(data: String, password: Option<String>) -> napi::Result<SshKeyPair> {
    russh_keys::decode_secret_key(&data, password.as_deref())
        .map_err(|e| WrappedError::from(russh::Error::from(e)).into())
        .map(|key| SshKeyPair { inner: key })
}

#[napi]
pub fn is_pageant_running() -> bool {
    #[cfg(windows)]
    return pageant::is_pageant_running();

    #[cfg(unix)]
    false
}
