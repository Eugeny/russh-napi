use std::sync::Arc;

use napi::bindgen_prelude::Uint8Array;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi_derive::napi;
use russh_keys::agent::client::{AgentClient, AgentStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::error::WrappedError;

#[napi]
pub enum AgentConnectionKind {
    Pageant,
    Pipe,
    Unix,
}

#[napi]
pub struct AgentConnection {
    pub kind: AgentConnectionKind,
    pub path: Option<String>,
}

#[napi]
impl AgentConnection {
    #[napi]
    pub fn new(kind: AgentConnectionKind, path: Option<String>) -> Self {
        Self { kind, path }
    }
}

pub async fn get_agent_client(
    connection: &AgentConnection,
) -> Result<AgentClient<impl AgentStream + Send>, WrappedError> {
    match connection.kind {
        AgentConnectionKind::Pageant => {
            #[cfg(windows)]
            return Ok(AgentClient::connect_pageant().await.dynamic());
            #[cfg(not(windows))]
            Err(russh_keys::Error::AgentFailure.into())
        }
        AgentConnectionKind::Pipe => {
            #[cfg(windows)]
            return Ok(AgentClient::connect_named_pipe(
                &connection.path.clone().unwrap_or_default(),
            )
            .await
            .map_err(WrappedError::from)?
            .dynamic());
            #[cfg(not(windows))]
            Err(russh_keys::Error::AgentFailure.into())
        }
        AgentConnectionKind::Unix => {
            #[cfg(unix)]
            return Ok(
                AgentClient::connect_uds(&connection.path.clone().unwrap_or_default())
                    .await
                    .map_err(WrappedError::from)?
                    .dynamic(),
            );
            #[cfg(not(unix))]
            Err(russh_keys::Error::AgentFailure.into())
        }
    }
}

#[napi]
pub struct SshAgentStream {
    writer: Arc<Mutex<Option<tokio::io::WriteHalf<Box<dyn AgentStream + Send + Unpin>>>>>,
}

#[napi]
impl SshAgentStream {
    #[napi]
    pub async fn write(&self, data: Uint8Array) -> napi::Result<()> {
        let mut writer = self.writer.lock().await;
        if let Some(writer) = writer.as_mut() {
            writer.write_all(&data).await.map_err(|_| {
                napi::Error::new(
                    napi::Status::GenericFailure,
                    "Failed to send data to channel",
                )
            })?;
        }
        Ok(())
    }

    #[napi]
    pub async fn close(&self) -> napi::Result<()> {
        self.writer.lock().await.take();
        Ok(())
    }
}

#[napi]
pub async fn connect_agent(
    connection: &AgentConnection,
    callback: ThreadsafeFunction<Uint8Array>,
) -> napi::Result<SshAgentStream> {
    let stream = get_agent_client(&connection).await?.into_inner();
    let (mut r, w) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(Some(w)));

    tokio::spawn({
        let writer = writer.clone();
        async move {
            loop {
                let buf = &mut [0u8; 4096];
                match r.read(buf).await {
                    Ok(n) => {
                        let buf = buf[..n].to_vec();
                        callback.call(Ok(buf.into()), ThreadsafeFunctionCallMode::NonBlocking);
                        if n == 0 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            writer.lock().await.take();
        }
    });
    Ok(SshAgentStream { writer })
}
