use std::sync::Arc;

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use russh_sftp::client::fs::DirEntry;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, FileType, OpenFlags};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::error::WrappedError;

#[allow(dead_code)]
#[napi]
pub const OPEN_READ: u32 = OpenFlags::READ.bits();

#[allow(dead_code)]
#[napi]
pub const OPEN_WRITE: u32 = OpenFlags::WRITE.bits();

#[allow(dead_code)]
#[napi]
pub const OPEN_APPEND: u32 = OpenFlags::APPEND.bits();

#[allow(dead_code)]
#[napi]
pub const OPEN_CREATE: u32 = OpenFlags::CREATE.bits();

#[allow(dead_code)]
#[napi]
pub const OPEN_TRUNCATE: u32 = OpenFlags::TRUNCATE.bits();

#[napi]
#[derive(Debug, Clone)]
pub struct SftpFileMetadata {
    inner: FileAttributes,
    pub size: String, // u64
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub gid: Option<u32>,
    pub group: Option<String>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

#[napi]
impl SftpFileMetadata {
    #[napi]
    pub fn type_(&self) -> SftpFileType {
        self.inner.file_type().into()
    }
}

impl From<&FileAttributes> for SftpFileMetadata {
    fn from(value: &FileAttributes) -> Self {
        Self {
            inner: value.clone(),
            size: format!("{}", value.size.unwrap_or(0)),
            uid: value.uid,
            user: value.user.clone(),
            gid: value.gid,
            group: value.group.clone(),
            permissions: value.permissions,
            atime: value.atime,
            mtime: value.mtime,
        }
    }
}

#[napi]
pub enum SftpFileType {
    Directory,
    File,
    Symlink,
    Other,
}

impl From<FileType> for SftpFileType {
    fn from(value: FileType) -> Self {
        match value {
            FileType::Dir => SftpFileType::Directory,
            FileType::File => SftpFileType::File,
            FileType::Symlink => SftpFileType::Symlink,
            FileType::Other => SftpFileType::Other,
        }
    }
}

#[napi]
pub struct SftpDirEntry {
    pub name: String,
    pub type_: SftpFileType,
    metadata: SftpFileMetadata,
}

#[napi]
impl SftpDirEntry {
    #[napi]
    pub fn metadata(&self) -> SftpFileMetadata {
        self.metadata.clone()
    }
}

impl From<DirEntry> for SftpDirEntry {
    fn from(entry: DirEntry) -> Self {
        SftpDirEntry {
            name: entry.file_name(),
            type_: entry.file_type().into(),
            metadata: SftpFileMetadata::from(&entry.metadata()),
        }
    }
}

#[napi]
pub struct SftpFile {
    handle: Arc<Mutex<russh_sftp::client::fs::File>>,
}

#[napi]
impl SftpFile {
    #[napi]
    pub async fn read(&self, n: u32) -> napi::Result<Uint8Array> {
        let mut handle = self.handle.lock().await;
        let mut buf = Vec::with_capacity(n as usize);
        let len = handle
            .read_buf(&mut buf)
            .await
            .map_err(WrappedError::from)?;
        Ok(Uint8Array::from(&buf[..len]))
    }

    #[napi]
    pub async fn write_all(&self, data: Uint8Array) -> napi::Result<()> {
        let mut handle = self.handle.lock().await;
        handle.write_all(&data).await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn flush(&self) -> napi::Result<()> {
        let mut handle = self.handle.lock().await;
        handle.flush().await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn shutdown(&self) -> napi::Result<()> {
        let mut handle = self.handle.lock().await;
        handle.shutdown().await.map_err(WrappedError::from)?;
        Ok(())
    }
}

#[napi]
pub struct SftpChannel {
    pub channel_id: u32,
    handle: Arc<Mutex<SftpSession>>,
}

#[napi]
impl SftpChannel {
    pub fn new(id: u32, ch: SftpSession) -> Self {
        SftpChannel {
            channel_id: id,
            handle: Arc::new(Mutex::new(ch)),
        }
    }

    #[napi]
    pub async fn read_dir(&self, path: String) -> napi::Result<Vec<SftpDirEntry>> {
        let handle = self.handle.lock().await;
        let result = handle.read_dir(path).await.map_err(WrappedError::from)?;
        Ok(result.map(Into::into).collect::<_>())
    }

    #[napi]
    pub async fn stat(&self, path: String) -> napi::Result<SftpFileMetadata> {
        let handle = self.handle.lock().await;
        let result = (&handle.metadata(path).await.map_err(WrappedError::from)?).into();
        Ok(result)
    }

    #[napi]
    pub async fn create_dir(&self, path: String) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle.create_dir(path).await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn readlink(&self, path: String) -> napi::Result<String> {
        let handle = self.handle.lock().await;
        let link = handle.read_link(path).await.map_err(WrappedError::from)?;
        Ok(link)
    }

    #[napi]
    pub async fn rename(&self, src: String, dst: String) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle.rename(src, dst).await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn chmod(&self, path: String, mode: u32) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        let mut metadata = handle.metadata(&path).await.map_err(WrappedError::from)?;
        metadata.permissions = Some(mode);
        handle
            .set_metadata(path, metadata)
            .await
            .map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn remove_dir(&self, path: String) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle.remove_dir(path).await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn remove_file(&self, path: String) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle.remove_file(path).await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn close(&self) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle.close().await.map_err(WrappedError::from)?;
        Ok(())
    }

    #[napi]
    pub async fn open(&self, path: String, mode: u32) -> napi::Result<SftpFile> {
        let handle = self.handle.lock().await;
        let f = handle
            .open_with_flags(
                path,
                OpenFlags::from_bits(mode).ok_or(napi::Error::from_reason("incorrect mode"))?,
            )
            .await
            .map_err(WrappedError::from)?;

        Ok(SftpFile {
            handle: Arc::new(Mutex::new(f)),
        })
    }
}
