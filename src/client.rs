use std::net::SocketAddr;

use thiserror::Error;
use tokio::net::UdpSocket;

use crate::client::ClientError::{
    FailedConnection, FailedParsingUDPResponse, FailedRadiusPacketEncoding,
    FailedReceivingResponse, FailedSendingPacket, FailedUdpSocketBinding,
};
use crate::packet::Packet;

#[derive(Error, Debug)]
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
}

pub struct Client {}

impl Client {
    const MAX_DATAGRAM_SIZE: usize = 65507;

    pub async fn send_packet(
        remote_addr: &SocketAddr,
        request_packet: &Packet,
    ) -> Result<Packet, ClientError> {
        // TODO retransmission

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
        match conn.connect(remote_addr).await {
            Ok(_) => {}
            Err(e) => return Err(FailedConnection(remote_addr.to_string(), e.to_string())),
        };

        let request_data = match request_packet.encode() {
            Ok(encoded) => encoded,
            Err(e) => return Err(FailedRadiusPacketEncoding(format!("{:?}", e))),
        };

        match conn.send(request_data.as_slice()).await {
            Ok(_) => {}
            Err(e) => return Err(FailedSendingPacket(remote_addr.to_string(), e.to_string())),
        };

        let mut buf = vec![0; Self::MAX_DATAGRAM_SIZE];
        let len = match conn.recv(&mut buf).await {
            Ok(len) => len,
            Err(e) => {
                return Err(FailedReceivingResponse(
                    remote_addr.to_string(),
                    e.to_string(),
                ))
            }
        };

        match Packet::decode(&buf[..len].to_vec(), request_packet.get_secret()) {
            Ok(response_packet) => Ok(response_packet),
            Err(e) => Err(FailedParsingUDPResponse(format!("{:?}", e))),
        }
    }
}
