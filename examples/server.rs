#[macro_use]
extern crate log;

use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::signal;

use radius_rs::code::Code;
use radius_rs::request::Request;
use radius_rs::request_handler::RequestHandler;
use radius_rs::rfc2865;
use radius_rs::secret_provider::{SecretProvider, SecretProviderError};
use radius_rs::server::Server;

#[tokio::main]
async fn main() {
    env_logger::init();

    let server_future = Server::run(
        "0.0.0.0",
        1812,
        1500,
        true,
        MyRequestHandler {},
        MySecretProvider {},
        signal::ctrl_c(),
    );

    let result = server_future.await;
    info!("{:?}", result);
}

struct MyRequestHandler {}

#[async_trait]
impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.get_packet();
        let maybe_user_name_attr = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password_attr = rfc2865::lookup_user_password(req_packet);

        let user_name = maybe_user_name_attr.unwrap().to_string().unwrap();
        let user_password = String::from_utf8(
            maybe_user_password_attr
                .unwrap()
                .to_user_password(req_packet.get_secret(), req_packet.get_authenticator())
                .unwrap(),
        )
        .unwrap();
        let code = if user_name == "admin" && user_password == "p@ssw0rd" {
            Code::AccessAccept
        } else {
            Code::AccessReject
        };
        info!("response => {:?} to {}", code, req.get_remote_addr());

        conn.send_to(
            &req_packet.make_response_packet(code).encode().unwrap(),
            req.get_remote_addr(),
        )
        .await?;
        Ok(())
    }
}

struct MySecretProvider {}

impl SecretProvider for MySecretProvider {
    fn fetch_secret(&self, _remote_addr: SocketAddr) -> Result<Vec<u8>, SecretProviderError> {
        let bs = b"secret".to_vec();
        Ok(bs)
    }
}
