use std::borrow::Cow;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use channel::NewSshChannel;
use key::{SshKeyPair, SshPublicKey};
use log::debug;
use napi::bindgen_prelude::{Promise, Uint8Array};
use napi::module_init;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use russh::client::{AuthResult, DisconnectReason};
use russh::keys::agent::AgentIdentity;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::{ChannelId, MethodSet};
use tokio::sync::Mutex;

use error::WrappedError;

mod agent;
mod channel;
mod error;
mod key;
mod sftp;
mod transport;

pub use agent::*;
pub use key::is_pageant_running;
pub use key::parse_key;
pub use key::HashAlgorithm;
use transport::SshTransport;

#[module_init]
fn init() {
    env_logger::init();
    debug!("russh-napi initialized");
}

pub struct SSHClientHandler {
    pub server_key_callback: ThreadsafeFunction<SshPublicKey, Promise<bool>>,
    pub data_callback: ThreadsafeFunction<(u32, Uint8Array)>,
    pub extended_data_callback: ThreadsafeFunction<(u32, u32, Uint8Array)>,
    pub eof_callback: ThreadsafeFunction<u32>,
    pub close_callback: ThreadsafeFunction<u32>,
    pub disconnect_callback: ThreadsafeFunction<Option<napi::Error>>,
    pub x11_channel_open_callback: ThreadsafeFunction<(NewSshChannel, String, u32)>,
    pub tcpip_channel_open_callback: ThreadsafeFunction<(NewSshChannel, String, u32, String, u32)>,
    pub agent_channel_open_callback: ThreadsafeFunction<NewSshChannel>,
    pub banner_callback: ThreadsafeFunction<String>,
}

#[napi]
pub fn supported_ciphers() -> Vec<String> {
    russh::cipher::ALL_CIPHERS
        .iter()
        .map(|x| x.as_ref().to_string())
        .collect()
}

#[napi]
pub fn supported_kex_algorithms() -> Vec<String> {
    russh::kex::ALL_KEX_ALGORITHMS
        .iter()
        .map(|x| x.as_ref().to_string())
        .collect()
}

#[napi]
pub fn supported_macs() -> Vec<String> {
    russh::mac::ALL_MAC_ALGORITHMS
        .iter()
        .map(|x| x.as_ref().to_string())
        .collect()
}

#[napi]
pub fn supported_compression_algorithms() -> Vec<String> {
    russh::compression::ALL_COMPRESSION_ALGORITHMS
        .iter()
        .map(|x| x.as_ref().to_string())
        .collect()
}

#[napi]
pub fn supported_key_types() -> Vec<String> {
    russh::keys::key::ALL_KEY_TYPES
        .iter()
        .map(|x| x.as_ref().to_string())
        .collect()
}

impl russh::client::Handler for SSHClientHandler {
    type Error = WrappedError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // todo handle certs
        let response = self
            .server_key_callback
            .call_async(Ok(SshPublicKey::from(server_public_key.public_key())))
            .await?
            .await?;

        Ok(response)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        self.data_callback.call(
            Ok((channel.into(), data.into())),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        self.extended_data_callback.call(
            Ok((channel.into(), ext, data.into())),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        self.eof_callback
            .call(Ok(channel.into()), ThreadsafeFunctionCallMode::NonBlocking);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        self.close_callback
            .call(Ok(channel.into()), ThreadsafeFunctionCallMode::NonBlocking);
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        self.disconnect_callback.call(
            Ok(match reason {
                DisconnectReason::Error(e) => Some(e.into()),
                DisconnectReason::ReceivedDisconnect(_) => None,
            }),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
        Ok(())
    }

    async fn server_channel_open_x11(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        originator_address: &str,
        originator_port: u32,
        reply: russh::ChannelOpenHandleInner<russh::client::Msg>,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.x11_channel_open_callback.call(
            Ok((channel.into(), originator_address.into(), originator_port)),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: russh::ChannelOpenHandleInner<russh::client::Msg>,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.tcpip_channel_open_callback.call(
            Ok((
                channel.into(),
                connected_address.into(),
                connected_port,
                originator_address.into(),
                originator_port,
            )),
            ThreadsafeFunctionCallMode::NonBlocking,
        );
        Ok(())
    }

    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        reply: russh::ChannelOpenHandleInner<russh::client::Msg>,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.agent_channel_open_callback
            .call(Ok(channel.into()), ThreadsafeFunctionCallMode::NonBlocking);
        Ok(())
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        self.banner_callback
            .call(Ok(banner.into()), ThreadsafeFunctionCallMode::NonBlocking);
        Ok(())
    }
}

#[napi]
#[derive(Debug, Clone)]
pub struct KeyboardInteractiveAuthenticationPrompt {
    pub prompt: String,
    pub echo: bool,
}

impl From<russh::client::Prompt> for KeyboardInteractiveAuthenticationPrompt {
    fn from(p: russh::client::Prompt) -> Self {
        KeyboardInteractiveAuthenticationPrompt {
            prompt: p.prompt,
            echo: p.echo,
        }
    }
}

#[napi]
pub struct KeyboardInteractiveAuthenticationState {
    pub state: String,
    pub partial_success: bool,
    pub name: Option<String>,
    pub instructions: Option<String>,
    pub remaining_methods: Vec<String>,
    prompts: Option<Vec<KeyboardInteractiveAuthenticationPrompt>>,
}

#[napi]
impl KeyboardInteractiveAuthenticationState {
    #[napi]
    pub fn prompts(&self) -> Option<Vec<KeyboardInteractiveAuthenticationPrompt>> {
        self.prompts.clone()
    }
}

impl From<russh::client::KeyboardInteractiveAuthResponse>
    for KeyboardInteractiveAuthenticationState
{
    fn from(r: russh::client::KeyboardInteractiveAuthResponse) -> Self {
        match r {
            russh::client::KeyboardInteractiveAuthResponse::Success => {
                KeyboardInteractiveAuthenticationState {
                    state: "success".into(),
                    remaining_methods: vec![],
                    partial_success: false,
                    instructions: None,
                    prompts: None,
                    name: None,
                }
            }
            russh::client::KeyboardInteractiveAuthResponse::Failure {
                remaining_methods,
                partial_success,
            } => KeyboardInteractiveAuthenticationState {
                state: "failure".into(),
                partial_success,
                instructions: None,
                remaining_methods: remaining_methods.iter().map(|x| x.into()).collect(),
                prompts: None,
                name: None,
            },
            russh::client::KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => KeyboardInteractiveAuthenticationState {
                state: "infoRequest".to_string(),
                name: Some(name),
                partial_success: false,
                remaining_methods: vec![],
                instructions: Some(instructions),
                prompts: Some(prompts.into_iter().map(Into::into).collect()),
            },
        }
    }
}

#[napi]
pub struct SshAuthResult {
    pub success: bool,
    pub partial_success: bool,
    pub remaining_methods: Vec<String>,
}

impl From<AuthResult> for SshAuthResult {
    fn from(r: AuthResult) -> Self {
        match r {
            AuthResult::Success => SshAuthResult {
                partial_success: false,
                remaining_methods: vec![],
                success: true,
            },
            AuthResult::Failure {
                partial_success,
                remaining_methods,
            } => SshAuthResult {
                success: false,
                partial_success,
                remaining_methods: remaining_methods.iter().map(|x| x.into()).collect(),
            },
        }
    }
}

#[napi]
pub struct SshClient {
    handle: Arc<Mutex<russh::client::Handle<SSHClientHandler>>>,
}

#[napi]
impl SshClient {
    #[napi]
    pub async fn authenticate_none(&self, username: String) -> napi::Result<SshAuthResult> {
        let mut handle = self.handle.lock().await;
        handle
            .authenticate_none(username)
            .await
            .map_err(WrappedError::from)
            .map_err(Into::into)
            .map(Into::into)
    }

    #[napi]
    pub async fn authenticate_password(
        &self,
        username: String,
        password: String,
    ) -> napi::Result<SshAuthResult> {
        let mut handle = self.handle.lock().await;
        handle
            .authenticate_password(username, password)
            .await
            .map_err(WrappedError::from)
            .map_err(Into::into)
            .map(Into::into)
    }

    #[napi]
    pub async fn authenticate_publickey(
        &self,
        username: String,
        key: &SshKeyPair,
        hash_algorithm: Option<HashAlgorithm>,
    ) -> napi::Result<SshAuthResult> {
        let mut handle: tokio::sync::MutexGuard<'_, russh::client::Handle<SSHClientHandler>> =
            self.handle.lock().await;
        let hash_algorithm = match hash_algorithm {
            Some(x) => x.into(),
            None => handle
                .best_supported_rsa_hash()
                .await
                .map_err(WrappedError::from)?
                .flatten(),
        };
        handle
            .authenticate_publickey(
                username,
                PrivateKeyWithHashAlg::new(Arc::new(key.inner.clone()), hash_algorithm),
            )
            .await
            .map_err(WrappedError::from)
            .map_err(Into::into)
            .map(Into::into)
    }

    #[napi]
    pub async fn start_keyboard_interactive_authentication(
        &self,
        username: String,
    ) -> napi::Result<KeyboardInteractiveAuthenticationState> {
        let mut handle = self.handle.lock().await;
        handle
            .authenticate_keyboard_interactive_start(username, None)
            .await
            .map_err(WrappedError::from)
            .map_err(Into::into)
            .map(Into::into)
    }

    #[napi]
    pub async fn respond_to_keyboard_interactive_authentication(
        &self,
        responses: Vec<String>,
    ) -> napi::Result<KeyboardInteractiveAuthenticationState> {
        let mut handle = self.handle.lock().await;
        handle
            .authenticate_keyboard_interactive_respond(responses)
            .await
            .map_err(WrappedError::from)
            .map_err(Into::into)
            .map(Into::into)
    }

    #[napi]
    pub async fn authenticate_agent(
        &self,
        username: String,
        connection: &AgentConnection,
        specific_key: Option<&SshPublicKey>,
    ) -> napi::Result<SshAuthResult> {
        let mut handle = self.handle.lock().await;

        let mut agent = get_agent_client(connection).await?;

        let keys = match specific_key {
            Some(k) => {
                debug!("Trying specified key {:?}", k.inner());
                vec![k.inner().clone().into()]
            }
            None => agent
                .request_identities()
                .await
                .map_err(WrappedError::from)?,
        };

        let mut last_auth_result = AuthResult::Failure {
            remaining_methods: MethodSet::empty(),
            partial_success: false,
        };

        let best_hash = handle
            .best_supported_rsa_hash()
            .await
            .map_err(|e| napi::Error::from(WrappedError::from(e)))?
            .flatten();

        for key in keys {
            debug!("Trying key {key:?}");
            let result = match key {
                AgentIdentity::PublicKey { key, .. } => {
                    handle
                        .authenticate_publickey_with(&username, key.clone(), best_hash, &mut agent)
                        .await
                }
                AgentIdentity::Certificate { certificate, .. } => {
                    handle
                        .authenticate_certificate_with(
                            &username,
                            certificate,
                            best_hash,
                            &mut agent,
                        )
                        .await
                }
            };
            let ret = result.map_err(|e| napi::Error::from(WrappedError::from(e)))?;
            if ret.success() {
                return Ok(ret.into());
            }
            last_auth_result = ret;
        }

        Ok(last_auth_result.into())
    }

    #[napi]
    pub async fn channel_open_session(&self) -> napi::Result<NewSshChannel> {
        let handle = self.handle.lock().await;
        let ch = handle
            .channel_open_session()
            .await
            .map_err(WrappedError::from)?;
        Ok(ch.into())
    }

    #[napi]
    pub async fn tcpip_forward(&self, address: String, port: u32) -> napi::Result<u32> {
        let handle = self.handle.lock().await;
        let port = handle
            .tcpip_forward(address, port)
            .await
            .map_err(WrappedError::from)?;
        Ok(port)
    }

    #[napi]
    pub async fn cancel_tcpip_forward(&self, address: String, port: u32) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle
            .cancel_tcpip_forward(address, port)
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn channel_open_direct_tcpip(
        &self,
        address: String,
        port: u32,
        originator_address: String,
        originator_port: u32,
    ) -> napi::Result<NewSshChannel> {
        let handle = self.handle.lock().await;
        let ch = handle
            .channel_open_direct_tcpip(address, port, originator_address, originator_port)
            .await
            .map_err(WrappedError::from)?;
        Ok(ch.into())
    }

    #[napi]
    pub async fn disconnect(&self) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    transport: &SshTransport,
    cipher_algos: Option<Vec<String>>,
    kex_algos: Option<Vec<String>>,
    key_algos: Option<Vec<String>>,
    mac_algos: Option<Vec<String>>,
    compression_algos: Option<Vec<String>>,
    connection_timeout_seconds: Option<u32>,
    keepalive_interval_seconds: Option<u32>,
    keepalive_max: u32,
    server_key_callback: ThreadsafeFunction<SshPublicKey, Promise<bool>>,
    data_callback: ThreadsafeFunction<(u32, Uint8Array)>,
    extended_data_callback: ThreadsafeFunction<(u32, u32, Uint8Array)>,
    eof_callback: ThreadsafeFunction<u32>,
    close_callback: ThreadsafeFunction<u32>,
    disconnect_callback: ThreadsafeFunction<Option<napi::Error>>,
    x11_channel_open_callback: ThreadsafeFunction<(NewSshChannel, String, u32)>,
    tcpip_channel_open_callback: ThreadsafeFunction<(NewSshChannel, String, u32, String, u32)>,
    agent_channel_open_callback: ThreadsafeFunction<NewSshChannel>,
    banner_callback: ThreadsafeFunction<String>,
) -> napi::Result<SshClient> {
    debug!("russh-napi connecting to {transport:?}");

    let handler = SSHClientHandler {
        server_key_callback,
        data_callback,
        extended_data_callback,
        eof_callback,
        close_callback,
        disconnect_callback,
        x11_channel_open_callback,
        tcpip_channel_open_callback,
        agent_channel_open_callback,
        banner_callback,
    };

    let mut preferred = russh::Preferred::DEFAULT.clone();
    if let Some(cipher_algos) = cipher_algos {
        preferred.cipher = cipher_algos
            .into_iter()
            .filter_map(|x| russh::cipher::Name::try_from(&x[..]).ok())
            .collect();
    }
    if let Some(kex_algos) = kex_algos {
        preferred.kex = kex_algos
            .into_iter()
            .filter_map(|x| russh::kex::Name::try_from(&x[..]).ok())
            .chain([
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
                russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            ])
            .collect();
    }
    if let Some(key_algos) = key_algos {
        preferred.key = Cow::Owned(
            key_algos
                .into_iter()
                .filter_map(|x| russh::keys::Algorithm::from_str(&x[..]).ok())
                .collect(),
        );
    }
    if let Some(mac_algos) = mac_algos {
        preferred.mac = mac_algos
            .into_iter()
            .filter_map(|x| russh::mac::Name::try_from(&x[..]).ok())
            .collect();
    }
    if let Some(compression_algos) = compression_algos {
        preferred.compression = compression_algos
            .into_iter()
            .filter_map(|x| russh::compression::Name::try_from(&x[..]).ok())
            .collect();
    }

    let cfg = russh::client::Config {
        preferred,
        keepalive_interval: keepalive_interval_seconds.map(|x| Duration::from_secs(x as u64)),
        keepalive_max: keepalive_max as usize,
        ..Default::default()
    };

    let Some(transport) = transport.take().await else {
        return Err(napi::Error::new(
            napi::Status::GenericFailure,
            "Transport already used",
        ));
    };

    let connection_fut = russh::client::connect_stream(Arc::new(cfg), transport, handler);
    let handle = if let Some(connection_timeout_seconds) = connection_timeout_seconds {
        tokio::time::timeout(
            Duration::from_secs(connection_timeout_seconds as u64),
            connection_fut,
        )
        .await
        .map_err(|_| napi::Error::new(napi::Status::GenericFailure, "Connection timeout"))?
    } else {
        connection_fut.await
    }?;

    Ok(SshClient {
        handle: Arc::new(Mutex::new(handle)),
    })
}
