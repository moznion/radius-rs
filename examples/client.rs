#[macro_use]
extern crate log;
use radius_rs::client::Client;
use radius_rs::code::Code;
use radius_rs::packet::Packet;
use radius_rs::rfc2865;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    env_logger::init();

    let remote_addr: SocketAddr = "127.0.0.1:1812".parse().unwrap();

    let mut req_packet = Packet::new(Code::AccessRequest, &b"secret".to_vec());
    rfc2865::add_user_name(&mut req_packet, "admin");
    rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap(); // TODO

    let res = Client::send_packet(&remote_addr, &req_packet).await;
    info!("response: {:?}", res);
}
