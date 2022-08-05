#[macro_use]
extern crate log;

use std::net::SocketAddr;
use std::{io, process};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::signal;

use radius::core::code::Code;
use radius::core::packet::Packet;
use radius::core::request::Request;
use radius::core::eap::{EAP, EAPType, EAPCode};
use radius::core::message_authenticator::MessageAuthenticator;
use radius::core::rfc2865;
use radius::core::rfc2869;
use radius::server::{RequestHandler, SecretProvider, SecretProviderError, Server};

#[tokio::main]
async fn main() {
    env_logger::init();

    // start UDP listening
    let mut server = Server::listen("0.0.0.0", 1812, MyRequestHandler {}, MySecretProvider {})
        .await
        .unwrap();
    server.set_buffer_size(1500); // default value: 1500
    server.set_skip_authenticity_validation(false); // default value: false

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

impl MyRequestHandler {
//     Authenticating peer     NAS                    RADIUS server
// -------------------     ---                    -------------
//                         <- EAP-Request/
//                         Identity
// EAP-Response/
// Identity (MyID) ->
//                         RADIUS Access-Request/
//                         EAP-Message/EAP-Response/
//                         (MyID) ->
//                                                <- RADIUS
//                                                Access-Challenge/
//                                                EAP-Message/EAP-Request
//                                                OTP/OTP Challenge
//                         <- EAP-Request/
//                         OTP/OTP Challenge
// EAP-Response/
// OTP, OTPpw ->
//                         RADIUS Access-Request/
//                         EAP-Message/EAP-Response/
//                         OTP, OTPpw ->
//                                                 <- RADIUS
//                                                 Access-Accept/
//                                                 EAP-Message/EAP-Success
//                                                 (other attributes)
//                         <- EAP-Success
    pub async fn handle_eap_identity(&self, conn: &UdpSocket, req: &Request, ieap: &EAP ) -> Result<usize, io::Error> {
        // Verify Message-Authenticator from Identity Access-Request
        let req_packet = req.get_packet();
        let incoming = match rfc2869::lookup_message_authenticator(&req_packet) {
            Some(m) => MessageAuthenticator::from_bytes(&m),
            None => {
                println!("No authenticator found");
                MessageAuthenticator::new()
            }
        };
        let validator = MessageAuthenticator::from_access_request(&req_packet);
        assert_eq!(validator, incoming);
        // Create response structure
        let mut ac_packet = req_packet.make_response_packet(Code::AccessChallenge);
        let mut eap = EAP::new();
        // let mut eap = ieap.clone();
        eap.code = EAPCode::Request;
        eap.typ  = EAPType::MD5Challenge;
        eap.id   = ieap.id;
        // eap.data = b"challengeval".to_vec();
        eap.len  = eap.recalc_len();
        rfc2869::add_eap_message(&mut ac_packet, &eap.to_bytes()[..]);
        // Calculate final Message-Authenticator
        let outgoing = MessageAuthenticator::for_response(&ac_packet);
        // Apply final Message-Authenticator to outgoing buffer
        ac_packet = outgoing.authenticate_packet(&ac_packet).unwrap();
        println!("Response EAP: {}", &eap);
        println!("Respose Message-Authenticator: {}", &outgoing);
        let result = conn.send_to(&ac_packet.encode().unwrap(), req.get_remote_addr()).await.unwrap();
        Ok(result)
    }
}

#[async_trait]
impl RequestHandler<(), io::Error> for MyRequestHandler {
    async fn handle_radius_request(
        &self,
        conn: &UdpSocket,
        req: &Request,
    ) -> Result<(), io::Error> {
        let req_packet = req.get_packet();
        // println!("Req:\n{:#?}", req_packet.clone());
        let maybe_user_name_attr = rfc2865::lookup_user_name(req_packet);
        let maybe_user_password_attr = rfc2865::lookup_user_password(req_packet);
        info!("maybe usr pass looked up");
        let maybe_eap_message = rfc2869::lookup_eap_message(req_packet);
        info!("maybe eap looked up");
        let eap_message = match rfc2869::lookup_eap_message(req_packet) {
            Some(e) => {
                let ieap = EAP::from_bytes(&e);
                println!("EAP Message: {}", &ieap);
                match ieap.typ {
                    EAPType::Identity => {
                        let result = self.handle_eap_identity(conn, req, &ieap).await.unwrap();
                        println!("Sent challenge-response {} bytes", &result);
                    }
                    _ => {
                        println!("EAPType not handled");
                    }
                }
                ieap
            },
            None => {
                println!("No eap message found");
                EAP::new()
            }
        };
        let user_name = maybe_user_name_attr.unwrap().unwrap();
        let user_password = match maybe_user_password_attr {
            Some(e) => match e {
                Ok(m) => String::from_utf8(m).unwrap(),
                Err(e) => {
                    error!("Could not decode user password due to:\n{}\n", e);
                    "".to_owned()
                }
            },
            None => {
                info!("No user password found");
                "".to_owned()
            }
        };

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
        let bs = b"somesecretval".to_vec();
        Ok(bs)
    }
}
