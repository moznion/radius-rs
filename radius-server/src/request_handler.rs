use async_trait::async_trait;
use tokio::net::UdpSocket;

use radius::request::Request;

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
