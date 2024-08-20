use std::sync::Arc;

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use tokio::sync::Mutex;

use crate::error::WrappedError;

#[napi]
pub struct SshChannel {
    handle: Arc<Mutex<Option<russh::Channel<russh::client::Msg>>>>,
}

impl From<russh::Channel<russh::client::Msg>> for SshChannel {
    fn from(ch: russh::Channel<russh::client::Msg>) -> Self {
        SshChannel {
            handle: Arc::new(Mutex::new(Some(ch))),
        }
    }
}

macro_rules! lock_channel {
    ($self: expr, $handle: ident) => {
        let locked = $self.handle.lock().await;
        let Some(ref $handle) = *locked else {
            return Err(napi::Error::new(
                napi::Status::GenericFailure,
                "Channel is already consumed",
            ));
        };
    };
}

#[napi]
impl SshChannel {
    pub async fn take(&self) -> Option<russh::Channel<russh::client::Msg>> {
        let mut handle = self.handle.lock().await;
        handle.take()
    }

    #[napi]
    pub async fn id(&self) -> napi::Result<u32> {
        lock_channel!(self, handle);
        Ok(handle.id().into())
    }

    #[napi]
    pub async fn request_pty(
        &self,
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle
            .request_pty(
                false,
                &term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                &[],
            )
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn request_shell(&self) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle
            .request_shell(true)
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn request_exec(&self, command: String) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle
            .exec(true, command)
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn request_x11_forwarding(
        &self,
        single_connection: bool,
        x11_protocol: String,
        x11_cookie: String,
        screen: u32,
    ) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle
            .request_x11(false, single_connection, &x11_protocol, &x11_cookie, screen)
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn request_agent_forwarding(&self) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle
            .agent_forward(false)
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn window_change(
        &self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle
            .window_change(col_width, row_height, pix_width, pix_height)
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn data(&self, data: Uint8Array) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle.data(&data[..]).await.map_err(|_| {
            napi::Error::new(
                napi::Status::GenericFailure,
                "Failed to send data to channel",
            )
        })?;
        Ok(())
    }

    #[napi]
    pub async fn eof(&self) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle.eof().await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn close(&self) -> napi::Result<()> {
        lock_channel!(self, handle);
        handle.close().await.map_err(WrappedError::from)?;
        Ok(())
    }
}
