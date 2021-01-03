use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::time::sleep;

use radius::core::code::Code;
use radius::core::request::Request;
use radius::core::rfc2865;
use radius::server::{RequestHandler, SecretProvider, SecretProviderError};

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

        let mut resp_packet = req_packet.make_response_packet(code);
        rfc2865::add_user_name(&mut resp_packet, user_name.as_str());
        conn.send_to(&resp_packet.encode().unwrap(), req.get_remote_addr())
            .await?;
        Ok(())
    }
}

struct LongTimeTakingHandler {}

#[async_trait]
impl RequestHandler<(), io::Error> for LongTimeTakingHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        sleep(Duration::from_secs(30)).await;
        let req_packet = req.get_packet();
        let resp_packet = req_packet.make_response_packet(Code::AccessReject);
        conn.send_to(&resp_packet.encode().unwrap(), req.get_remote_addr())
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::sync::oneshot;

    use radius::client::{Client, ClientError};
    use radius::core::code::Code;
    use radius::core::packet::Packet;
    use radius::core::rfc2865;

    use crate::test::{LongTimeTakingHandler, MyRequestHandler, MySecretProvider};
    use radius::server::Server;

    #[tokio::test]
    async fn test_runner() {
        test_access_request().await;
        test_socket_timeout().await;
    }

    async fn test_access_request() {
        let (sender, receiver) = oneshot::channel::<()>();

        let port = 1812;

        let mut server = Server::listen("0.0.0.0", port, MyRequestHandler {}, MySecretProvider {})
            .await
            .unwrap();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        let remote_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let client = Client::new(None, None);

        let mut req_packet = Packet::new(Code::AccessRequest, &b"secret".to_vec());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await.unwrap();
        let maybe_user_name = rfc2865::lookup_user_name(&res);
        let maybe_user_pass = rfc2865::lookup_user_password(&res);
        assert_eq!(res.get_code(), Code::AccessAccept);
        assert_eq!(maybe_user_name.is_some(), true);
        assert_eq!(maybe_user_name.unwrap().unwrap(), "admin");
        assert_eq!(maybe_user_pass.is_none(), true);

        let mut req_packet = Packet::new(Code::AccessRequest, &b"secret".to_vec());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"INVALID-PASS").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await.unwrap();
        assert_eq!(res.get_code(), Code::AccessReject);

        sender.send(()).unwrap();
        server_proc.await.unwrap();
    }

    async fn test_socket_timeout() {
        let (sender, receiver) = oneshot::channel::<()>();

        let port = 1812;

        let mut server = Server::listen(
            "0.0.0.0",
            port,
            LongTimeTakingHandler {},
            MySecretProvider {},
        )
        .await
        .unwrap();

        let server_proc = tokio::spawn(async move {
            server.run(receiver).await.unwrap();
        });

        let remote_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        let client = Client::new(None, Some(Duration::from_secs(0)));

        let mut req_packet = Packet::new(Code::AccessRequest, &b"secret".to_vec());
        rfc2865::add_user_name(&mut req_packet, "admin");
        rfc2865::add_user_password(&mut req_packet, b"p@ssw0rd").unwrap();
        let res = client.send_packet(&remote_addr, &req_packet).await;

        let err = res.unwrap_err();
        match err {
            ClientError::SocketTimeoutError() => {}
            _ => panic!("unexpected error: {}", err),
        }

        sender.send(()).unwrap();
        server_proc.await.unwrap();
    }
}
