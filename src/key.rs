use crate::error::WrappedError;
use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use russh::keys::{HashAlg, PublicKeyBase64};

#[napi]
#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<HashAlgorithm> for Option<HashAlg> {
    fn from(value: HashAlgorithm) -> Self {
        match value {
            HashAlgorithm::Sha1 => None,
            HashAlgorithm::Sha256 => Some(HashAlg::Sha256),
            HashAlgorithm::Sha512 => Some(HashAlg::Sha512),
        }
    }
}

#[napi]
#[derive(Clone)]
pub struct SshPublicKey {
    inner: russh::keys::PublicKey,
}

#[napi]
impl SshPublicKey {
    #[napi]
    pub fn algorithm(&self) -> String {
        self.inner.algorithm().to_string()
    }

    #[napi]
    pub fn fingerprint(&self) -> String {
        format!("{}", self.inner.fingerprint(HashAlg::Sha256))
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

impl From<russh::keys::PublicKey> for SshPublicKey {
    fn from(inner: russh::keys::PublicKey) -> Self {
        SshPublicKey { inner }
    }
}

#[napi]
#[derive(Clone)]
pub struct SshKeyPair {
    pub(crate) inner: russh::keys::PrivateKey,
}

#[napi]
impl SshKeyPair {
    #[napi]
    pub fn public_key(&self) -> SshPublicKey {
        self.inner.public_key().clone().into()
    }
}

#[napi]
pub fn parse_key(data: String, password: Option<String>) -> napi::Result<SshKeyPair> {
    russh::keys::decode_secret_key(&data, password.as_deref())
        .map_err(|e| WrappedError::from(russh::Error::from(e)).into())
        .map(|key| SshKeyPair { inner: key })
}

#[napi]
pub fn is_pageant_running() -> bool {
    #[cfg(windows)]
    return pageant::wmmessage::is_pageant_running();

    #[cfg(unix)]
    false
}

/// Parse a public key from OpenSSH format string (e.g., "ssh-ed25519 AAAA... comment")
#[napi]
pub fn parse_public_key(data: String) -> napi::Result<SshPublicKey> {
    russh::keys::PublicKey::from_openssh(&data)
        .map_err(|e| WrappedError::from(russh::Error::from(e)).into())
        .map(|key| SshPublicKey { inner: key })
}

impl SshPublicKey {
    pub fn inner(&self) -> &russh::keys::PublicKey {
        &self.inner
    }
}
