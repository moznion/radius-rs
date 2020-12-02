#[macro_use]
extern crate log;
use radius::code::Code;
use radius::packet::Packet;
use radius::rfc2865;
use radius_client::client::Client;
use std::net::SocketAddr;
use tokio::time::Duration;

#[tokio::main]
async fn main() {
    env_logger::init();

    let remote_addr: SocketAddr = "127.0.0.1:1812".parse().unwrap();

    let mut req_packet = Packet::new(Code::AccessRequest, &b"secret".to_vec());
    rfc2865::add_user_name(&mut req_packet, "admin");
    rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap();

    let client = Client::new(Some(Duration::from_secs(3)), Some(Duration::from_secs(5)));
    let res = client.send_packet(&remote_addr, &req_packet).await;
    info!("response: {:?}", res);
}
