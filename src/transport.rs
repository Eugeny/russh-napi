use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_http_proxy::http_connect_tokio;
use delegate::delegate;
use napi_derive::napi;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::sync::Mutex;
use tokio_socks::tcp::Socks5Stream;

use crate::channel::SshChannel;

#[napi]
pub struct SshTransport(Arc<Mutex<Option<SshTransportInner>>>);

pub(crate) enum SshTransportInner {
    Socket(TcpStream),
    Command(Child),
    SshChannel(russh::ChannelStream<russh::client::Msg>),
    SocksProxy(tokio_socks::tcp::socks5::Socks5Stream<TcpStream>),
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
            SshTransportInner::SshChannel(_) | SshTransportInner::SocksProxy(_) => {
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

    #[napi]
    pub async fn new_socks_proxy(
        proxy_host: String,
        proxy_port: u16,
        target_host: String,
        target_port: u16,
    ) -> napi::Result<SshTransport> {
        let stream = Socks5Stream::connect(
            (proxy_host.as_ref(), proxy_port),
            (target_host, target_port),
        )
        .await
        .map_err(crate::WrappedError::from)?;

        Ok(Self(Arc::new(Mutex::new(Some(
            SshTransportInner::SocksProxy(stream),
        )))))
    }

    #[napi]
    pub async fn new_http_proxy(
        proxy_host: String,
        proxy_port: u16,
        target_host: String,
        target_port: u16,
    ) -> napi::Result<SshTransport> {
        let mut socket = tokio::net::TcpStream::connect((proxy_host, proxy_port)).await?;
        socket.set_nodelay(true)?;
        http_connect_tokio(&mut socket, target_host.as_str(), target_port)
            .await
            .map_err(crate::WrappedError::from)?;

        Ok(Self(Arc::new(Mutex::new(Some(SshTransportInner::Socket(
            socket,
        ))))))
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
            SshTransportInner::SocksProxy(stream) => Pin::new(stream),
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
            SshTransportInner::SocksProxy(stream) => Pin::new(stream),
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
            SshTransportInner::SocksProxy(stream) => Pin::new(stream),
        } {
            fn is_write_vectored(&self) -> bool;
        }
    }
}
