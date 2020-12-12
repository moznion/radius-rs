use std::net::SocketAddr;

use crate::core::packet::Packet;

/// RADIUS request object.
pub struct Request {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    packet: Packet,
}

impl Request {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr, packet: Packet) -> Self {
        Self {
            local_addr,
            remote_addr,
            packet,
        }
    }

    pub fn get_local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn get_remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn get_packet(&self) -> &Packet {
        &self.packet
    }
}
