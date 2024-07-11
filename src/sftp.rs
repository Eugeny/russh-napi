use std::sync::Arc;

use napi_derive::napi;
use russh_sftp::client::fs::DirEntry;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileType;
use tokio::sync::Mutex;

use crate::error::WrappedError;

#[napi]
pub struct SftpChannel {
    pub channel_id: u32,
    handle: Arc<Mutex<SftpSession>>,
}

impl SftpChannel {
    pub fn new(id: u32, ch: SftpSession) -> Self {
        SftpChannel {
            channel_id: id,
            handle: Arc::new(Mutex::new(ch)),
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

#[napi]
pub struct SftpDirEntry {
    pub name: String,
    pub type_: SftpFileType,
    pub size: String, // u64
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub gid: Option<u32>,
    pub group: Option<String>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

impl From<DirEntry> for SftpDirEntry {
    fn from(entry: DirEntry) -> Self {
        SftpDirEntry {
            name: entry.file_name(),
            type_: match entry.file_type() {
                FileType::Dir => SftpFileType::Directory,
                FileType::File => SftpFileType::File,
                FileType::Symlink => SftpFileType::Symlink,
                FileType::Other => SftpFileType::Other,
            },
            size: format!("{}", entry.metadata().size.unwrap_or(0)),
            uid: entry.metadata().uid,
            user: entry.metadata().user,
            gid: entry.metadata().gid,
            group: entry.metadata().group,
            permissions: entry.metadata().permissions,
            atime: entry.metadata().atime,
            mtime: entry.metadata().mtime,
        }
    }
}

#[napi]
impl SftpChannel {
    #[napi]
    pub async fn read_dir(&self, path: String) -> napi::Result<Vec<SftpDirEntry>> {
        let handle = self.handle.lock().await;
        let result = handle.read_dir(path).await.map_err(WrappedError::from)?;
        Ok(result.map(Into::into).collect::<_>())
    }

    #[napi]
    pub async fn create_dir(&self, path: String) -> napi::Result<()> {
        let handle = self.handle.lock().await;
        handle.create_dir(path).await.map_err(WrappedError::from)?;
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
}
