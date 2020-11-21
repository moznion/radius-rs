use std::convert::TryInto;
use std::io::Write;

use rand::Rng;

use crate::attributes::Attributes;
use crate::code::Code;

const MAX_PACKET_LENGTH: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    code: Code,
    identifier: u8,
    authenticator: Vec<u8>,
    secret: Vec<u8>,
    attributes: Attributes,
}

impl Packet {
    pub fn new(code: &Code, secret: &Vec<u8>) -> Self {
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

    pub fn parse(bs: &Vec<u8>, secret: &Vec<u8>) -> Result<Self, String> {
        if bs.len() < 20 {
            return Err("radius packet doesn't have enough length of bytes; that has to be at least 20 bytes".to_owned());
        }

        let len = match bs[2..4].try_into() {
            Ok(v) => u16::from_be_bytes(v),
            Err(e) => return Err(e.to_string()),
        } as usize;
        if len < 20 || len > MAX_PACKET_LENGTH || bs.len() < len {
            return Err("invalid radius packat lengt".to_owned());
        }

        let attributes = match Attributes::parse_attributes(&bs[20..len].to_vec()) {
            Ok(attributes) => attributes,
            Err(e) => return Err(e),
        };

        Ok(Packet {
            code: Code::from(bs[0]),
            identifier: bs[1],
            authenticator: bs[4..20].to_owned(),
            secret: secret.to_owned(),
            attributes,
        })
    }

    pub fn response(&self, code: &Code) -> Self {
        Packet {
            code: code.clone(),
            identifier: self.identifier,
            authenticator: self.authenticator.clone(),
            secret: self.secret.clone(),
            attributes: Attributes(vec![]),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let bs = match self.marshal_binary() {
            Ok(bs) => bs,
            Err(e) => return Err(e.to_string()),
        };

        match self.code {
            Code::AccessRequest | Code::StatusServer => Ok(bs),
            Code::AccessAccept | Code::AccessReject | Code::AccountingRequest | Code::AccessChallenge | Code::DisconnectRequest | Code::DisconnectACK | Code::DisconnectNAK | Code::CoARequest | Code::CoAACK | Code::CoANAK => {
                // TODO length checking
                let mut buf: Vec<u8> = bs[..4].to_vec();
                match self.code {
                    Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                        buf.extend(vec![
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        ]);
                    }
                    _ => {
                        buf.extend(self.authenticator.clone());
                    }
                }
                buf.extend(bs[20..].to_vec());
                buf.extend(&self.secret);
                Ok(md5::compute(buf).to_vec())
            }
            _ => Err("unknown packet code".to_owned())
        }
    }

    pub fn marshal_binary(&self) -> Result<Vec<u8>, String> {
        let attributes_len = match self.attributes.attributes_encoded_len() {
            Ok(attributes_len) => attributes_len,
            Err(e) => return Err(e.to_string())
        };

        let size = 20 + attributes_len;
        if size as usize > MAX_PACKET_LENGTH {
            return Err("packet is too large".to_owned());
        }

        let mut bs: Vec<u8> = Vec::new();
        bs.push(self.code.clone() as u8);
        bs.push(self.identifier);
        bs.extend(u16::to_be_bytes(size).to_vec());
        bs.extend(self.authenticator.to_vec());
        Ok(self.attributes.encode(bs))
    }

    pub fn is_authentic_response(response: Vec<u8>, request: Vec<u8>, secret: Vec<u8>) -> bool {
        if response.len() < 20 || request.len() < 20 || secret.len() == 0 {
            return false;
        }

        md5::compute([
            &response[..4],
            &request[4..20],
            &response[20..], // TODO length
            &secret,
        ].concat()).to_vec().eq(&response[4..20].to_vec())
    }

    pub fn is_authentic_request(request: Vec<u8>, secret: Vec<u8>) -> bool {
        if request.len() < 20 || secret.len() == 0 {
            return false;
        }

        match Code::from(request[0]) {
            Code::AccessRequest | Code::StatusServer => true,
            Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                md5::compute([
                    &request[..4],
                    &vec![
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    ],
                    &request[20..], // TODO length
                    &secret,
                ].concat()).to_vec().eq(&request[4..20].to_vec())
            }
            _ => false
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::code::Code;
    use crate::packet::Packet;

    #[test]
    fn test_for_rfc2865_7_1() -> Result<(), String> {
        // ref: https://tools.ietf.org/html/rfc2865#section-7.1

        let secret: Vec<u8> = "xyzzy5461".as_bytes().to_vec();
        let request: Vec<u8> = vec![
            0x01, 0x00, 0x00, 0x38, 0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83, 0xd5, 0xcb,
            0x98, 0xf4, 0x22, 0x7a, 0x01, 0x06, 0x6e, 0x65, 0x6d, 0x6f, 0x02, 0x12, 0x0d, 0xbe, 0x70, 0x8d,
            0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a, 0x0a, 0xee, 0x04, 0x06, 0xc0, 0xa8,
            0x01, 0x10, 0x05, 0x06, 0x00, 0x00, 0x00, 0x03,
        ];

        let packet = Packet::parse(&request, &secret)?;
        assert_eq!(packet.code, Code::AccessRequest);
        assert_eq!(packet.identifier, 0);

        // TODO

        Ok(())
    }
}
