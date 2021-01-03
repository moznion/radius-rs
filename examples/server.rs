#[macro_use]
extern crate log;

use std::net::SocketAddr;
use std::{io, process};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::signal;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::core::rfc2865;
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

#[tokio::main]
async fn main() {
    env_logger::init();

    // start UDP listening
    let mut server = Server::listen(
        "0.0.0.0",
        1812,
        1500,
        false,
        MyRequestHandler {},
        MySecretProvider {},
    )
    .await
    .unwrap();

    // once it has reached here, a RADIUS server is now ready
    info!(
        "serve is now ready: {}",
        server.get_listen_address().unwrap()
    );

    // start the loop to handle the RADIUS requests
    let result = server.run(signal::ctrl_c()).await;
    info!("{:?}", result);
    if result.is_err() {
        process::exit(1);
    }
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

        let user_name = maybe_user_name_attr.unwrap().unwrap();
        let user_password = String::from_utf8(maybe_user_password_attr.unwrap().unwrap()).unwrap();
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
