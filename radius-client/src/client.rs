use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use radius::packet::Packet;

use crate::client::ClientError::{
    FailedConnection, FailedParsingUDPResponse, FailedRadiusPacketEncoding,
    FailedReceivingResponse, FailedSendingPacket, FailedUdpSocketBinding,
};

#[derive(Error, PartialEq, Debug)]
pub enum ClientError {
    #[error("failed to bind a UDP socket => `{0}`")]
    FailedUdpSocketBinding(String),
    #[error("failed to connect to `{0}` => `{1}`")]
    FailedConnection(String, String),
    #[error("failed to encode a RADIUS request => `{0}`")]
    FailedRadiusPacketEncoding(String),
    #[error("failed to send a UDP datagram to `{0}` => `{1}`")]
    FailedSendingPacket(String, String),
    #[error("failed to receive the UDP response from `{0}` => `{1}`")]
    FailedReceivingResponse(String, String),
    #[error("failed to parse a UDP response into a RADIUS packet => `{0}`")]
    FailedParsingUDPResponse(String),
    #[error("connection timeout")]
    ConnectionTimeoutError(),
    #[error("socket timeout")]
    SocketTimeoutError(),
}

/// A basic implementation of the RADIUS client.
pub struct Client {
    connection_timeout: Option<Duration>,
    socket_timeout: Option<Duration>,
}

impl Client {
    const MAX_DATAGRAM_SIZE: usize = 65507;

    /// A constructor for a client.
    ///
    /// # Arguments
    ///
    /// * `connection_timeout` - A duration of connection timeout. If the connection is not established in time, the `ConnectionTimeoutError` occurs.
    ///                          If this value is `None`, it never timed-out.
    /// * `socket_timeout` - A duration of socket timeout. If the response is not returned in time, the `SocketTimeoutError` occurs.
    ///                      If this value is `None`, it never timed-out.
    pub fn new(connection_timeout: Option<Duration>, socket_timeout: Option<Duration>) -> Self {
        Client {
            connection_timeout,
            socket_timeout,
        }
    }

    /// This method sends a packet to the destination.
    ///
    /// This method doesn't support auto retransmission when something failed, so if you need such a feature you have to implement that.
    pub async fn send_packet(
        &self,
        remote_addr: &SocketAddr,
        request_packet: &Packet,
    ) -> Result<Packet, ClientError> {
        let local_addr: SocketAddr = if remote_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .unwrap();

        let conn = match UdpSocket::bind(local_addr).await {
            Ok(conn) => conn,
            Err(e) => return Err(FailedUdpSocketBinding(e.to_string())),
        };

        match self.connection_timeout {
            Some(connection_timeout) => {
                match timeout(connection_timeout, self.connect(&conn, remote_addr)).await {
                    Ok(conn_establish_res) => conn_establish_res,
                    Err(_) => Err(ClientError::ConnectionTimeoutError()),
                }
            }
            None => self.connect(&conn, remote_addr).await,
        }?;

        let request_data = match request_packet.encode() {
            Ok(encoded) => encoded,
            Err(e) => return Err(FailedRadiusPacketEncoding(format!("{:?}", e))),
        };

        let response = match self.socket_timeout {
            Some(socket_timeout) => {
                match timeout(
                    socket_timeout,
                    self.request(&conn, &request_data, remote_addr),
                )
                .await
                {
                    Ok(response) => response,
                    Err(_) => Err(ClientError::SocketTimeoutError()),
                }
            }
            None => self.request(&conn, &request_data, remote_addr).await,
        }?;

        match Packet::decode(&response.to_vec(), request_packet.get_secret()) {
            Ok(response_packet) => Ok(response_packet),
            Err(e) => Err(FailedParsingUDPResponse(format!("{:?}", e))),
        }
    }

    async fn connect(&self, conn: &UdpSocket, remote_addr: &SocketAddr) -> Result<(), ClientError> {
        match conn.connect(remote_addr).await {
            Ok(_) => Ok(()),
            Err(e) => Err(FailedConnection(remote_addr.to_string(), e.to_string())),
        }
    }

    async fn request(
        &self,
        conn: &UdpSocket,
        request_data: &[u8],
        remote_addr: &SocketAddr,
    ) -> Result<Vec<u8>, ClientError> {
        match conn.send(request_data).await {
            Ok(_) => {}
            Err(e) => return Err(FailedSendingPacket(remote_addr.to_string(), e.to_string())),
        };

        let mut buf = vec![0; Self::MAX_DATAGRAM_SIZE];
        match conn.recv(&mut buf).await {
            Ok(len) => Ok(buf[..len].to_vec()),
            Err(e) => Err(FailedReceivingResponse(
                remote_addr.to_string(),
                e.to_string(),
            )),
        }
    }
}
