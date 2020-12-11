use std::net::SocketAddr;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretProviderError {
    /// An error that represents a failure to fetch a secret value from the provider.
    #[error("failed to fetch a secret value: {0}")]
    FailedFetchingError(String),
    /// An error that represents a generic (i.e. unclassified) error that occurs on the secret value provider.
    #[error("unexpected error: {0}")]
    GenericError(String),
}

/// SecretProvider is a provider for secret value.
pub trait SecretProvider: 'static + Sync + Send {
    /// This method has to implement the generator of the secret value to verify the request of
    /// `Accounting-Response`, `Accounting-Response` and `CoA-Request`.
    fn fetch_secret(&self, remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError>;
}
