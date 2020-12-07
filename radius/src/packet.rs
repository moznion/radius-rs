use std::convert::TryInto;

use rand::Rng;
use thiserror::Error;

use crate::attributes::Attributes;
use crate::avp::{AVPType, AVP};
use crate::code::Code;

const MAX_PACKET_LENGTH: usize = 4096;
const RADIUS_PACKET_HEADER_LENGTH: usize = 20; // i.e. minimum packet length

#[derive(Error, Debug, PartialEq)]
pub enum PacketError {
    #[error("radius packet doesn't have enough length of bytes; it has to be at least {0} bytes")]
    InsufficientPacketLengthError(usize),
    #[error("invalid radius packet length: {0}")]
    InvalidPacketLengthError(usize),
    #[error("unexpected decoding error: {0}")]
    UnexpectedDecodingError(String),
    #[error("failed to decode the packet: {0}")]
    DecodingError(String),
    #[error("failed to encode the packet: {0}")]
    EncodingError(String),
    #[error("Unknown radius packet code: {0}")]
    UnknownCodeError(String),
}

/// This struct represents a packet of RADIUS for request and response.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    code: Code,
    identifier: u8,
    authenticator: Vec<u8>,
    secret: Vec<u8>,
    attributes: Attributes,
}

impl Packet {
    /// Constructor for a Packet.
    pub fn new(code: Code, secret: &[u8]) -> Self {
        let mut rng = rand::thread_rng();
        let authenticator = (0..16).map(|_| rng.gen()).collect::<Vec<u8>>();
        Packet {
            code: code.to_owned(),
            identifier: rng.gen(),
            authenticator,
            secret: secret.to_owned(),
            attributes: Attributes(vec![]),
        }
    }

    pub fn get_code(&self) -> Code {
        self.code
    }

    pub fn get_identifier(&self) -> u8 {
        self.identifier
    }

    pub fn get_secret(&self) -> &Vec<u8> {
        &self.secret
    }

    pub fn get_authenticator(&self) -> &Vec<u8> {
        &self.authenticator
    }

    /// This decodes bytes into a Packet.
    pub fn decode(bs: &[u8], secret: &[u8]) -> Result<Self, PacketError> {
        if bs.len() < RADIUS_PACKET_HEADER_LENGTH {
            return Err(PacketError::InsufficientPacketLengthError(
                RADIUS_PACKET_HEADER_LENGTH,
            ));
        }

        let len = match bs[2..4].try_into() {
            Ok(v) => u16::from_be_bytes(v),
            Err(e) => return Err(PacketError::UnexpectedDecodingError(e.to_string())),
        } as usize;
        if len < RADIUS_PACKET_HEADER_LENGTH || len > MAX_PACKET_LENGTH || bs.len() < len {
            return Err(PacketError::InvalidPacketLengthError(len));
        }

        let attributes = match Attributes::decode(&bs[RADIUS_PACKET_HEADER_LENGTH..len].to_vec()) {
            Ok(attributes) => attributes,
            Err(e) => return Err(PacketError::DecodingError(e)),
        };

        Ok(Packet {
            code: Code::from(bs[0]),
            identifier: bs[1],
            authenticator: bs[4..RADIUS_PACKET_HEADER_LENGTH].to_owned(),
            secret: secret.to_owned(),
            attributes,
        })
    }

    /// This method makes a response packet according to self (i.e. request packet).
    pub fn make_response_packet(&self, code: Code) -> Self {
        Packet {
            code,
            identifier: self.identifier,
            authenticator: self.authenticator.clone(),
            secret: self.secret.clone(),
            attributes: Attributes(vec![]),
        }
    }

    /// This method encodes the Packet into bytes.
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        let mut bs = match self.marshal_binary() {
            Ok(bs) => bs,
            Err(e) => return Err(PacketError::EncodingError(e)),
        };

        match self.code {
            Code::AccessRequest | Code::StatusServer => Ok(bs),
            Code::AccessAccept
            | Code::AccessReject
            | Code::AccountingRequest
            | Code::AccessChallenge
            | Code::DisconnectRequest
            | Code::DisconnectACK
            | Code::DisconnectNAK
            | Code::CoARequest
            | Code::CoAACK
            | Code::CoANAK => {
                let mut buf: Vec<u8> = bs[..4].to_vec();
                match self.code {
                    Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                        buf.extend(vec![
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                        ]);
                    }
                    _ => {
                        buf.extend(self.authenticator.clone()); // TODO take from `bs`?
                    }
                }
                buf.extend(bs[RADIUS_PACKET_HEADER_LENGTH..].to_vec());
                buf.extend(&self.secret);
                bs.splice(4..20, md5::compute(&buf).to_vec());

                Ok(bs)
            }
            _ => Err(PacketError::UnknownCodeError(format!("{:?}", self.code))),
        }
    }

    /*
     * Binary structure:
     *   0                   1                   2                   3
     *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |     Code      |  Identifier   |            Length             |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                                                               |
     *  |                         Authenticator                         |
     *  |                                                               |
     *  |                                                               |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |  Attributes ...
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-
     */
    fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        let encoded_avp = match self.attributes.encode() {
            Ok(encoded) => encoded,
            Err(e) => return Err(e),
        };

        let size = RADIUS_PACKET_HEADER_LENGTH as u16 + encoded_avp.len() as u16;
        if size as usize > MAX_PACKET_LENGTH {
            return Err("packet is too large".to_owned());
        }

        let mut bs: Vec<u8> = Vec::new();
        bs.push(self.code as u8);
        bs.push(self.identifier);
        bs.extend(u16::to_be_bytes(size).to_vec());
        bs.extend(self.authenticator.to_vec());
        bs.extend(match self.attributes.encode() {
            Ok(encoded) => encoded,
            Err(e) => return Err(e),
        });
        Ok(bs)
    }

    /// Returns whether the Packet is authentic response or not.
    pub fn is_authentic_response(response: &[u8], request: &[u8], secret: &[u8]) -> bool {
        if response.len() < RADIUS_PACKET_HEADER_LENGTH
            || request.len() < RADIUS_PACKET_HEADER_LENGTH
            || secret.is_empty()
        {
            return false;
        }

        md5::compute(
            [
                &response[..4],
                &request[4..RADIUS_PACKET_HEADER_LENGTH],
                &response[RADIUS_PACKET_HEADER_LENGTH..],
                &secret,
            ]
            .concat(),
        )
        .to_vec()
        .eq(&response[4..RADIUS_PACKET_HEADER_LENGTH].to_vec())
    }

    /// Returns whether the Packet is authentic request or not.
    pub fn is_authentic_request(request: &[u8], secret: &[u8]) -> bool {
        if request.len() < RADIUS_PACKET_HEADER_LENGTH || secret.is_empty() {
            return false;
        }

        match Code::from(request[0]) {
            Code::AccessRequest | Code::StatusServer => true,
            Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => md5::compute(
                [
                    &request[..4],
                    &[
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                    ],
                    &request[RADIUS_PACKET_HEADER_LENGTH..],
                    &secret,
                ]
                .concat(),
            )
            .to_vec()
            .eq(&request[4..RADIUS_PACKET_HEADER_LENGTH].to_vec()),
            _ => false,
        }
    }

    /// Add an AVP to the list of AVPs.
    pub fn add(&mut self, avp: AVP) {
        self.attributes.add(avp);
    }

    /// Add AVPs to the list of AVPs.
    pub fn extend(&mut self, avps: Vec<AVP>) {
        self.attributes.extend(avps)
    }

    /// Delete all of AVPs from the list according to given AVP type.
    pub fn delete(&mut self, typ: AVPType) {
        self.attributes.del(typ);
    }

    /// Returns an AVP that matches at first with the given AVP type. If there are not any matched ones, this returns `None`.
    pub fn lookup(&self, typ: AVPType) -> Option<&AVP> {
        self.attributes.lookup(typ)
    }

    /// Returns AVPs that match with the given AVP type.
    pub fn lookup_all(&self, typ: AVPType) -> Vec<&AVP> {
        self.attributes.lookup_all(typ)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::avp::AVP;
    use crate::code::Code;
    use crate::packet::{Packet, PacketError};
    use crate::rfc2865;

    #[test]
    fn test_for_rfc2865_7_1() -> Result<(), PacketError> {
        // ref: https://tools.ietf.org/html/rfc2865#section-7.1

        let secret: Vec<u8> = "xyzzy5461".as_bytes().to_vec();
        let request: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x38, 0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83,
            0xd5, 0xcb, 0x98, 0xf4, 0x22, 0x7a, 0x01, 0x06, 0x6e, 0x65, 0x6d, 0x6f, 0x02, 0x12,
            0x0d, 0xbe, 0x70, 0x8d, 0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a,
            0x0a, 0xee, 0x04, 0x06, 0xc0, 0xa8, 0x01, 0x10, 0x05, 0x06, 0x00, 0x00, 0x00, 0x03,
        ];

        let request_packet = Packet::decode(&request, &secret)?;
        assert_eq!(request_packet.code, Code::AccessRequest);
        assert_eq!(request_packet.identifier, 0);
        assert_eq!(
            rfc2865::lookup_user_name(&request_packet).unwrap().unwrap(),
            "nemo"
        );
        assert_eq!(
            rfc2865::lookup_user_password(&request_packet)
                .unwrap()
                .unwrap(),
            b"arctangent"
        );
        assert_eq!(
            rfc2865::lookup_nas_ip_address(&request_packet)
                .unwrap()
                .unwrap(),
            Ipv4Addr::from([192, 168, 1, 16]),
        );
        assert_eq!(
            rfc2865::lookup_nas_port(&request_packet).unwrap().unwrap(),
            3
        );
        assert_eq!(request_packet.encode().unwrap(), request);
        assert_eq!(Packet::is_authentic_request(&request, &secret), true);

        let response: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x26, 0x86, 0xfe, 0x22, 0x0e, 0x76, 0x24, 0xba, 0x2a, 0x10, 0x05,
            0xf6, 0xbf, 0x9b, 0x55, 0xe0, 0xb2, 0x06, 0x06, 0x00, 0x00, 0x00, 0x01, 0x0f, 0x06,
            0x00, 0x00, 0x00, 0x00, 0x0e, 0x06, 0xc0, 0xa8, 0x01, 0x03,
        ];
        let mut response_packet = request_packet.make_response_packet(Code::AccessAccept);
        rfc2865::add_service_type(&mut response_packet, rfc2865::SERVICE_TYPE_LOGIN_USER);
        rfc2865::add_login_service(&mut response_packet, rfc2865::LOGIN_SERVICE_TELNET);
        rfc2865::add_login_ip_host(&mut response_packet, &Ipv4Addr::from([192, 168, 1, 3]));
        assert_eq!(response_packet.encode().unwrap(), response);
        assert_eq!(
            Packet::is_authentic_response(&response, &request, &secret),
            true
        );

        Ok(())
    }

    #[test]
    fn test_for_rfc2865_7_2() -> Result<(), PacketError> {
        let secret: Vec<u8> = "xyzzy5461".as_bytes().to_vec();
        let request: Vec<u8> = vec![
            0x01, 0x01, 0x00, 0x47, 0x2a, 0xee, 0x86, 0xf0, 0x8d, 0x0d, 0x55, 0x96, 0x9c, 0xa5,
            0x97, 0x8e, 0x0d, 0x33, 0x67, 0xa2, 0x01, 0x08, 0x66, 0x6c, 0x6f, 0x70, 0x73, 0x79,
            0x03, 0x13, 0x16, 0xe9, 0x75, 0x57, 0xc3, 0x16, 0x18, 0x58, 0x95, 0xf2, 0x93, 0xff,
            0x63, 0x44, 0x07, 0x72, 0x75, 0x04, 0x06, 0xc0, 0xa8, 0x01, 0x10, 0x05, 0x06, 0x00,
            0x00, 0x00, 0x14, 0x06, 0x06, 0x00, 0x00, 0x00, 0x02, 0x07, 0x06, 0x00, 0x00, 0x00,
            0x01,
        ];

        let request_packet = Packet::decode(&request, &secret)?;
        assert_eq!(request_packet.get_code(), Code::AccessRequest);
        assert_eq!(request_packet.identifier, 1);
        assert_eq!(
            rfc2865::lookup_user_name(&request_packet).unwrap().unwrap(),
            "flopsy"
        );
        assert_eq!(
            rfc2865::lookup_nas_ip_address(&request_packet)
                .unwrap()
                .unwrap(),
            Ipv4Addr::from([192, 168, 1, 16]),
        );
        assert_eq!(
            rfc2865::lookup_nas_port(&request_packet).unwrap().unwrap(),
            20
        );
        assert_eq!(
            rfc2865::lookup_service_type(&request_packet)
                .unwrap()
                .unwrap(),
            rfc2865::SERVICE_TYPE_FRAMED_USER,
        );
        assert_eq!(
            rfc2865::lookup_framed_protocol(&request_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_PROTOCOL_PPP,
        );

        let response: Vec<u8> = vec![
            0x02, 0x01, 0x00, 0x38, 0x15, 0xef, 0xbc, 0x7d, 0xab, 0x26, 0xcf, 0xa3, 0xdc, 0x34,
            0xd9, 0xc0, 0x3c, 0x86, 0x01, 0xa4, 0x06, 0x06, 0x00, 0x00, 0x00, 0x02, 0x07, 0x06,
            0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0xff, 0xff, 0xff, 0xfe, 0x0a, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x0d, 0x06, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x06, 0x00, 0x00, 0x05,
            //    ^ incorrectly a 2 in the document
            0xdc,
        ];
        let response_packet = Packet::decode(&response, &secret).unwrap();

        assert_eq!(response_packet.get_code(), Code::AccessAccept);
        assert_eq!(response_packet.get_identifier(), 1);
        assert_eq!(
            rfc2865::lookup_service_type(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::SERVICE_TYPE_FRAMED_USER
        );
        assert_eq!(
            rfc2865::lookup_framed_protocol(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_PROTOCOL_PPP,
        );
        assert_eq!(
            rfc2865::lookup_framed_ip_address(&response_packet)
                .unwrap()
                .unwrap(),
            Ipv4Addr::from([255, 255, 255, 254]),
        );
        assert_eq!(
            rfc2865::lookup_framed_routing(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_ROUTING_NONE,
        );
        assert_eq!(
            rfc2865::lookup_framed_compression(&response_packet)
                .unwrap()
                .unwrap(),
            rfc2865::FRAMED_COMPRESSION_VAN_JACOBSON_TCP_IP,
        );
        assert_eq!(
            rfc2865::lookup_framed_mtu(&response_packet)
                .unwrap()
                .unwrap(),
            1500,
        );

        Ok(())
    }

    #[test]
    fn test_passwords() {
        let passwords = vec![
            b"".to_vec(),
            b"qwerty".to_vec(),
            b"helloworld1231231231231233489hegufudhsgdsfygdf8g".to_vec(),
        ];

        let secret = b"xyzzy5461";

        for password in passwords {
            let mut request_packet = Packet::new(Code::AccessRequest, secret);
            rfc2865::add_user_password(&mut request_packet, &password).unwrap();

            let encoded = request_packet.encode().unwrap();

            let decoded = Packet::decode(&encoded, secret).unwrap();
            assert_eq!(
                rfc2865::lookup_user_password(&decoded).unwrap().unwrap(),
                password
            );
        }
    }

    #[test]
    fn test_parse_invalid() {
        struct TestCase<'a> {
            plain_text: &'a str,
            expected_error: PacketError,
        };

        let test_cases = &[
            TestCase {
                plain_text: "\x01",
                expected_error: PacketError::InsufficientPacketLengthError(20),
            },
            TestCase {
                plain_text: "\x01\x7f\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                expected_error: PacketError::InvalidPacketLengthError(0),
            },
            TestCase {
                plain_text: "\x01\x7f\x7f\x7f\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                expected_error: PacketError::InvalidPacketLengthError(32639),
            },
            TestCase {
                plain_text: "\x00\x7f\x00\x16\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
                expected_error: PacketError::InvalidPacketLengthError(22),
            },
            TestCase {
                plain_text: "\x01\x01\x00\x16\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00",
                expected_error: PacketError::DecodingError("invalid attribute length".to_owned()),
            }
        ];

        let secret = b"12345";
        for test_case in test_cases {
            let result = Packet::decode(test_case.plain_text.as_bytes(), secret);
            assert_eq!(result.is_err(), true);
            assert_eq!(result.err().unwrap(), test_case.expected_error);
        }
    }

    #[test]
    fn test_packet_attribute_length_boundary() {
        let mut packet = Packet::new(Code::AccessRequest, b"12345");
        packet.add(AVP {
            typ: 1,
            value: vec![1; 253],
        });
        let encoded = packet.encode();
        assert_eq!(encoded.is_err(), false);

        let mut packet = Packet::new(Code::AccessRequest, b"12345");
        packet.add(AVP {
            typ: 1,
            value: vec![1; 254],
        });
        let encoded = packet.encode();
        assert_eq!(encoded.is_err(), true);
        assert_eq!(
            encoded.err().unwrap(),
            PacketError::EncodingError("attribute is too large".to_owned()),
        );
    }
}
