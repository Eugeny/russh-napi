use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use channel::SshChannel;
use key::{SshKeyPair, SshPublicKey};
use napi::bindgen_prelude::{Promise, Uint8Array};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use russh::client::DisconnectReason;
use russh::ChannelId;
use russh_sftp::client::SftpSession;
use sftp::SftpChannel;
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
use transport::SshTransport;

pub struct SSHClientHandler {
    pub server_key_callback: ThreadsafeFunction<SshPublicKey, Promise<bool>>,
    pub data_callback: ThreadsafeFunction<(u32, Uint8Array)>,
    pub extended_data_callback: ThreadsafeFunction<(u32, u32, Uint8Array)>,
    pub eof_callback: ThreadsafeFunction<u32>,
    pub close_callback: ThreadsafeFunction<u32>,
    pub disconnect_callback: ThreadsafeFunction<Option<napi::Error>>,
    pub x11_channel_open_callback: ThreadsafeFunction<(SshChannel, String, u32)>,
    pub tcpip_channel_open_callback: ThreadsafeFunction<(SshChannel, String, u32, String, u32)>,
    pub agent_channel_open_callback: ThreadsafeFunction<SshChannel>,
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
    russh_keys::key::ALL_KEY_TYPES
        .iter()
        .map(|x| x.as_ref().to_string())
        .collect()
}

#[async_trait]
impl russh::client::Handler for SSHClientHandler {
    type Error = WrappedError;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let response = self
            .server_key_callback
            .call_async(Ok(SshPublicKey::from(server_public_key.clone())))
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
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
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
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
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
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
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
    pub name: Option<String>,
    pub instructions: Option<String>,
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
                    instructions: None,
                    prompts: None,
                    name: None,
                }
            }
            russh::client::KeyboardInteractiveAuthResponse::Failure => {
                KeyboardInteractiveAuthenticationState {
                    state: "failure".into(),
                    instructions: None,
                    prompts: None,
                    name: None,
                }
            }
            russh::client::KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => KeyboardInteractiveAuthenticationState {
                state: "infoRequest".to_string(),
                name: Some(name),
                instructions: Some(instructions),
                prompts: Some(prompts.into_iter().map(Into::into).collect()),
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
    pub async fn authenticate_password(
        &self,
        username: String,
        password: String,
    ) -> napi::Result<bool> {
        let mut handle = self.handle.lock().await;
        handle
            .authenticate_password(username, password)
            .await
            .map_err(WrappedError::from)
            .map_err(Into::into)
    }

    #[napi]
    pub async fn authenticate_publickey(
        &self,
        username: String,
        key: &SshKeyPair,
    ) -> napi::Result<bool> {
        let mut handle = self.handle.lock().await;
        handle
            .authenticate_publickey(username, Arc::new(key.inner.clone()))
            .await
            .map_err(WrappedError::from)
            .map_err(Into::into)
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
            .map(|x| {
                dbg!(&x);
                x
            })
            .map(Into::into)
    }

    #[napi]
    pub async fn authenticate_agent(
        &self,
        username: String,
        connection: &AgentConnection,
    ) -> napi::Result<bool> {
        let mut handle = self.handle.lock().await;

        let mut agent = get_agent_client(connection).await?;

        let keys = agent
            .request_identities()
            .await
            .map_err(WrappedError::from)?;
        for key in keys {
            let (_agent, result) = handle.authenticate_future(&username, key, agent).await;
            agent = _agent;
            let ret = result.map_err(|e| napi::Error::from(WrappedError::from(e)))?;
            if ret {
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[napi]
    pub async fn channel_open_session(&self) -> napi::Result<SshChannel> {
        let handle = self.handle.lock().await;
        let ch = handle
            .channel_open_session()
            .await
            .map_err(WrappedError::from)?;
        Ok(ch.into())
    }

    #[napi]
    pub async fn tcpip_forward(&self, address: String, port: u32) -> napi::Result<u32> {
        let mut handle = self.handle.lock().await;
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
    ) -> napi::Result<SshChannel> {
        let handle = self.handle.lock().await;
        let ch = handle
            .channel_open_direct_tcpip(address, port, originator_address, originator_port)
            .await
            .map_err(WrappedError::from)?;
        Ok(ch.into())
    }

    #[napi]
    pub async fn channel_open_sftp(&self) -> napi::Result<SftpChannel> {
        let handle = self.handle.lock().await;
        let ch = handle
            .channel_open_session()
            .await
            .map_err(WrappedError::from)?;
        ch.request_subsystem(true, "sftp")
            .await
            .map_err(WrappedError::from)?;
        let id = ch.id();
        let sftp = SftpSession::new(ch.into_stream())
            .await
            .map_err(WrappedError::from)?;
        Ok(SftpChannel::new(id.into(), sftp))
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
    x11_channel_open_callback: ThreadsafeFunction<(SshChannel, String, u32)>,
    tcpip_channel_open_callback: ThreadsafeFunction<(SshChannel, String, u32, String, u32)>,
    agent_channel_open_callback: ThreadsafeFunction<SshChannel>,
    banner_callback: ThreadsafeFunction<String>,
) -> napi::Result<SshClient> {
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
            .collect();
    }
    if let Some(key_algos) = key_algos {
        preferred.key = key_algos
            .into_iter()
            .filter_map(|x| russh_keys::key::Name::try_from(&x[..]).ok())
            .collect();
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
        .map_err(WrappedError::from)?
    } else {
        connection_fut.await.map_err(WrappedError::from)?
    };

    Ok(SshClient {
        handle: Arc::new(Mutex::new(handle)),
    })
}
