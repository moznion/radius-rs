use async_trait::async_trait;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use thiserror::Error;
use tokio::net::UdpSocket;

use crate::core::packet::Packet;
use crate::core::request::Request;
use std::fmt::Debug;
use std::marker::PhantomData;

const DEFAULT_BUFFER_SIZE: usize = 1500;
const DEFAULT_SKIP_AUTHENTICITY_VALIDATION: bool = false;

/// A basic implementation of the RADIUS server.
///
/// ## Example Usage
/// - https://github.com/moznion/radius-rs/blob/HEAD/examples/server.rs
pub struct Server<X, E: Debug, T: RequestHandler<X, E>, U: SecretProvider> {
    skip_authenticity_validation: bool,
    buf_size: usize,
    conn_arc: Arc<UdpSocket>,
    request_handler_arc: Arc<T>,
    secret_provider_arc: Arc<U>,
    undergoing_requests_lock_arc: Arc<RwLock<HashSet<RequestKey>>>,
    _phantom_return_type: PhantomData<X>,
    _phantom_error_type: PhantomData<E>,
}

impl<X, E: Debug, T: RequestHandler<X, E>, U: SecretProvider> Server<X, E, T, U> {
    // NOTE: why it separates between `listen()` and `run()`.
    // Initially it uses a channel that given through the `run()` parameter to notify when a server becomes ready,
    // but that doesn't work because it never run the procedure until `await` called.
    // This means if it calls `await`, it blocks the procedure so it cannot consume a channel simultaneously.
    // Thus, it separates bootstrap sequence between `listen()` and `run()`.
    // `listen()`: Start UDP listening. After this function call is finished, the RADIUS server is ready.
    // `run()`: Start a loop to handle the RADIUS requests.

    /// Starts UDP listening for the RADIUS server.
    /// After this function call is finished, the RADIUS server becomes ready to handle the requests;
    /// then it calls `run()` method for a `Server` instance that returned by this function,
    /// it starts RADIUS request handling.
    ///
    /// ## Parameters
    ///
    /// - `host` - a host to listen (e.g. `0.0.0.0`)
    /// - `port` - a port number to listen (e.g. `1812`)
    /// - `request_handler` - a request handler for the RADIUS requests.
    /// - `secret_provider` - a provider for shared-secret value.
    pub async fn listen(
        host: &str,
        port: u16,
        request_handler: T,
        secret_provider: U,
    ) -> Result<Self, io::Error> {
        let undergoing_requests_lock_arc = Arc::new(RwLock::new(HashSet::new()));
        let request_handler_arc = Arc::new(request_handler);
        let secret_provider_arc = Arc::new(secret_provider);

        let address = format!("{}:{}", host, port);
        let conn = UdpSocket::bind(address).await?;
        let conn_arc = Arc::new(conn);

        Ok(Server {
            skip_authenticity_validation: DEFAULT_SKIP_AUTHENTICITY_VALIDATION,
            buf_size: DEFAULT_BUFFER_SIZE,
            conn_arc,
            request_handler_arc,
            secret_provider_arc,
            undergoing_requests_lock_arc,
            _phantom_return_type: Default::default(),
            _phantom_error_type: Default::default(),
        })
    }

    /// Starts the RADIUS requests handling.
    ///
    /// ## Parameters
    ///
    /// - `shutdown_trigger`: an implementation of the `Future` to interrupt to shutdown the RADIUS server (e.g. `signal::ctrl_c()`)
    pub async fn run(&mut self, shutdown_trigger: impl Future) -> Result<(), io::Error> {
        tokio::select! {
            res = self.run_loop() => {
                res
            }
            _ = shutdown_trigger => {
                info!("server is shutting down");
                Ok(())
            }
        }
    }

    /// Set a buffer size for receiving the request payload (default: `1500`).
    pub fn set_buffer_size(&mut self, buf_size: usize) {
        self.buf_size = buf_size;
    }

    /// Set a flag to specify whether to skip the authenticity validation or not (default: `false`).
    pub fn set_skip_authenticity_validation(&mut self, skip_authenticity_validation: bool) {
        self.skip_authenticity_validation = skip_authenticity_validation;
    }

    /// Returns the listening address.
    pub fn get_listen_address(&self) -> io::Result<SocketAddr> {
        self.conn_arc.local_addr()
    }

    async fn run_loop(&self) -> Result<(), io::Error> {
        let mut buf: Vec<u8> = vec![Default::default(); self.buf_size];

        loop {
            let conn = self.conn_arc.clone();
            let request_handler = self.request_handler_arc.clone();
            let secret_provider = self.secret_provider_arc.clone();

            let (size, remote_addr) = conn.recv_from(&mut buf).await?;

            let request_data = buf[..size].to_vec();

            let local_addr = match conn.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    error!(
                        "failed to get a local address from from a connection; {}",
                        e
                    );
                    continue;
                }
            };

            let undergoing_requests_lock = self.undergoing_requests_lock_arc.clone();
            let skip_authenticity_validation = self.skip_authenticity_validation;

            tokio::spawn(async move {
                Self::process_request(
                    conn,
                    &request_data,
                    local_addr,
                    remote_addr,
                    undergoing_requests_lock,
                    request_handler,
                    secret_provider,
                    skip_authenticity_validation,
                )
                .await;
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_request(
        conn: Arc<UdpSocket>,
        request_data: &[u8],
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        undergoing_requests_lock: Arc<RwLock<HashSet<RequestKey>>>,
        request_handler: Arc<T>,
        secret_provider: Arc<U>,
        skip_authenticity_validation: bool,
    ) {
        let secret: Vec<u8> = match secret_provider.fetch_secret(remote_addr) {
            Ok(secret) => secret,
            Err(e) => {
                error!(
                    "failed to fetch secret binary vector from the secret provider; {}",
                    e
                );
                return;
            }
        };
        if secret.is_empty() {
            error!("empty secret returned from secret source; empty secret is prohibited");
            return;
        }

        if !skip_authenticity_validation && !Packet::is_authentic_request(request_data, &secret) {
            info!("packet validation failed; bad secret");
            return;
        }

        let packet = match Packet::decode(request_data, &secret) {
            Ok(packet) => packet,
            Err(e) => {
                error!(
                    "failed to parse given request data to pack into the RADIUS packet; {}",
                    e
                );
                debug!("failed request data => {:?}", request_data);
                // TODO error handler support?
                return;
            }
        };

        let key = RequestKey {
            ip: remote_addr.to_string(),
            identifier: packet.get_identifier(),
        };
        let key_for_remove = key.clone();

        {
            let mut undergoing_requests = undergoing_requests_lock.write().unwrap();
            if undergoing_requests.contains(&key) {
                return;
            }
            undergoing_requests.insert(key);
        }

        match request_handler
            .handle_radius_request(
                conn.borrow(),
                &Request::new(local_addr, remote_addr, packet),
            )
            .await
        {
            Ok(_) => {}
            Err(e) => {
                println!("{:?}", e);
            }
        }

        let mut undergoing_requests = undergoing_requests_lock.write().unwrap();
        undergoing_requests.remove(&key_for_remove);
    }
}

/// RequestHandler is a handler for the received RADIUS request.
#[async_trait]
pub trait RequestHandler<T, E>: 'static + Sync + Send {
    /// This method has to implement the core feature of the server application what you need.
    ///
    /// # Arguments
    ///
    /// * conn - This connection is associated with the remote requester. In the most situations,
    ///          you have to send a response through this connection object.
    /// * request - This is a request object that comes from the remote requester.
    async fn handle_radius_request(&self, conn: &UdpSocket, request: &Request) -> Result<T, E>;
}

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
    /// This method has to implement the generator of the shared-secret value to verify the request.
    fn fetch_secret(&self, remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError>;
}

#[derive(PartialEq, Eq, Hash, Clone)]
struct RequestKey {
    ip: String,
    identifier: u8,
}
