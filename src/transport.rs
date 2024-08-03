use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use delegate::delegate;
use napi_derive::napi;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::sync::Mutex;

use crate::channel::SshChannel;

#[napi]
pub struct SshTransport(Arc<Mutex<Option<SshTransportInner>>>);

pub(crate) enum SshTransportInner {
    Socket(TcpStream),
    Command(Child),
    SshChannel(russh::ChannelStream<russh::client::Msg>),
}

impl Drop for SshTransportInner {
    fn drop(&mut self) {
        match self {
            SshTransportInner::Socket(socket) => {
                let _ = futures::executor::block_on(socket.shutdown());
            }
            SshTransportInner::Command(child) => {
                let _ = child.kill();
            }
            SshTransportInner::SshChannel(_) => {
                // just drop the stream
            }
        }
    }
}

#[napi]
impl SshTransport {
    #[napi]
    pub async fn new_socket(address: String) -> napi::Result<SshTransport> {
        let socket = tokio::net::TcpStream::connect(address.clone()).await?;
        socket.set_nodelay(true)?;
        Ok(Self(Arc::new(Mutex::new(Some(SshTransportInner::Socket(
            socket,
        ))))))
    }

    #[napi]
    pub async fn new_command(command: String, args: Vec<String>) -> napi::Result<SshTransport> {
        let child = tokio::process::Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()?;

        Ok(Self(Arc::new(Mutex::new(Some(
            SshTransportInner::Command(child),
        )))))
    }

    #[napi]
    pub async fn new_ssh_channel(channel: &SshChannel) -> napi::Result<SshTransport> {
        let Some(handle) = channel.take().await else {
            return Err(napi::Error::new(
                napi::Status::GenericFailure,
                "Channel is already consumed",
            ));
        };

        let stream = handle.into_stream();

        Ok(Self(Arc::new(Mutex::new(Some(
            SshTransportInner::SshChannel(stream),
        )))))
    }

    pub(crate) async fn take(&self) -> Option<SshTransportInner> {
        self.0.lock().await.take()
    }
}

impl AsyncRead for SshTransportInner {
    delegate! {
        to match self.get_mut() {
            SshTransportInner::Socket(stream) => Pin::new(stream),
            SshTransportInner::Command(child) => Pin::new(child.stdout.as_mut().unwrap()),
            SshTransportInner::SshChannel(stream) => Pin::new(stream),
        } {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<Result<(), std::io::Error>>;
        }
    }
}

impl AsyncWrite for SshTransportInner {
    delegate! {
        to match self.get_mut() {
            SshTransportInner::Socket(stream) => Pin::new(stream),
            SshTransportInner::Command(child) => Pin::new(child.stdin.as_mut().unwrap()),
            SshTransportInner::SshChannel(stream) => Pin::new(stream),
        } {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<Result<usize, std::io::Error>>;

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bufs: &[IoSlice<'_>],
            ) -> Poll<Result<usize, std::io::Error>>;

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;
        }
    }

    delegate! {
        to match self {
            SshTransportInner::Socket(stream) => Pin::new(stream),
            SshTransportInner::Command(child) => Pin::new(child.stdin.as_ref().unwrap()),
            SshTransportInner::SshChannel(stream) => Pin::new(stream),
        } {
            fn is_write_vectored(&self) -> bool;
        }
    }
}
