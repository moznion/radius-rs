use std::net::SocketAddr;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretProviderError {
    #[error("failed to fetch a secret value => `{0}`")]
    FailedFetching(String)
}

pub trait SecretProvider: Sync + Send {
    fn fetch_secret(&self, remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError>;
}
