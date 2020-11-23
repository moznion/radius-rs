use tokio::net::UdpSocket;

use crate::request::Request;

pub trait RequestHandler: Sync + Send {
    fn handle_radius_request(&self, conn: &UdpSocket, request: &Request);
}
