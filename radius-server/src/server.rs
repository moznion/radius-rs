use std::borrow::Borrow;
use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use tokio::net::UdpSocket;

use crate::request_handler::RequestHandler;
use crate::secret_provider::SecretProvider;
use radius::packet::Packet;
use radius::request::Request;
use std::fmt::Debug;

/// A basic implementation of the RADIUS server.
pub struct Server {}

impl Server {
    /// Start listening a UDP socket to process the RAIDUS requests.
    pub async fn run<X, E: Debug, T: RequestHandler<X, E>, U: SecretProvider>(
        host: &str,
        port: u16,
        buf_size: usize,
        skip_authenticity_validation: bool,
        request_handler: T,
        secret_provider: U,
        shutdown_trigger: impl Future,
    ) -> Result<(), io::Error> {
        tokio::select! {
            res = Self::run_loop(host, port, buf_size, skip_authenticity_validation, request_handler, secret_provider) => {
                res
            }
            _ = shutdown_trigger => {
                info!("server is shutting down");
                Ok(())
            }
        }
    }

    async fn run_loop<X, E: Debug, T: RequestHandler<X, E>, U: SecretProvider>(
        host: &str,
        port: u16,
        buf_size: usize,
        skip_authenticity_validation: bool,
        request_handler: T,
        secret_provider: U,
    ) -> Result<(), io::Error> {
        let address = format!("{}:{}", host, port);
        let conn = UdpSocket::bind(address).await?;

        let conn_arc = Arc::new(conn);
        let undergoing_requests_lock_arc = Arc::new(RwLock::new(HashSet::new()));
        let request_handler_arc = Arc::new(request_handler);
        let secret_provider_arc = Arc::new(secret_provider);

        let mut buf = vec![Default::default(); buf_size];
        loop {
            let conn = conn_arc.clone();
            let request_handler = request_handler_arc.clone();
            let secret_provider = secret_provider_arc.clone();

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

            let undergoing_requests_lock = undergoing_requests_lock_arc.clone();

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
    async fn process_request<X, E: Debug, T: RequestHandler<X, E>, U: SecretProvider>(
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

#[derive(PartialEq, Eq, Hash, Clone)]
struct RequestKey {
    ip: String,
    identifier: u8,
}
