use async_trait::async_trait;
use tokio::net::UdpSocket;

use radius::request::Request;

#[async_trait]
pub trait RequestHandler<T, E>: 'static + Sync + Send {
    async fn handle_radius_request(&self, conn: &UdpSocket, request: &Request) -> Result<T, E>;
}
