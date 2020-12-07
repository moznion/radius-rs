use std::net::SocketAddr;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretProviderError {
    #[error("failed to fetch a secret value => `{0}`")]
    FailedFetching(String),
}

/// SecretProvider is a provider for secret value.
pub trait SecretProvider: 'static + Sync + Send {
    /// This method has to implement the generator of the secret value to verify the request of
    /// `Accounting-Response`, `Accounting-Response` and `CoA-Request`.
    fn fetch_secret(&self, remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError>;
}
