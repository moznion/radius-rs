use std::convert::TryInto;

use rand::Rng;

use crate::attribute::Attribute;
use crate::attributes::{AVPType, Attributes};
use crate::code::Code;

const MAX_PACKET_LENGTH: usize = 4096;
const RADIUS_PACKET_HEADER_LENGTH: usize = 20; // i.e. minimum packet lengt

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    code: Code,
    identifier: u8,
    authenticator: Vec<u8>,
    secret: Vec<u8>,
    attributes: Attributes,
}

impl Packet {
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

    pub fn get_identifier(&self) -> u8 {
        self.identifier
    }

    pub fn get_secret(&self) -> &Vec<u8> {
        &self.secret
    }

    pub fn get_authenticator(&self) -> &Vec<u8> {
        &self.authenticator
    }

    pub fn parse(bs: &[u8], secret: &[u8]) -> Result<Self, String> {
        if bs.len() < RADIUS_PACKET_HEADER_LENGTH {
            return Err(format!("radius packet doesn't have enough length of bytes; that has to be at least {} bytes", RADIUS_PACKET_HEADER_LENGTH));
        }

        let len = match bs[2..4].try_into() {
            Ok(v) => u16::from_be_bytes(v),
            Err(e) => return Err(e.to_string()),
        } as usize;
        if len < RADIUS_PACKET_HEADER_LENGTH || len > MAX_PACKET_LENGTH || bs.len() < len {
            return Err("invalid radius packat lengt".to_owned());
        }

        let attributes =
            match Attributes::parse_attributes(&bs[RADIUS_PACKET_HEADER_LENGTH..len].to_vec()) {
                Ok(attributes) => attributes,
                Err(e) => return Err(e),
            };

        Ok(Packet {
            code: Code::from(bs[0]),
            identifier: bs[1],
            authenticator: bs[4..RADIUS_PACKET_HEADER_LENGTH].to_owned(),
            secret: secret.to_owned(),
            attributes,
        })
    }

    pub fn response(&self, code: Code) -> Self {
        Packet {
            code,
            identifier: self.identifier,
            authenticator: self.authenticator.clone(),
            secret: self.secret.clone(),
            attributes: Attributes(vec![]),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut bs = match self.marshal_binary() {
            Ok(bs) => bs,
            Err(e) => return Err(e),
        };

        debug!("encoded resp bs: {:?}", bs);
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
                // TODO length checking
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
                debug!("md5: {:?}", md5::compute(&buf).to_vec());
                debug!("encoded resp bs: {:?}", bs);

                Ok(bs)
            }
            _ => Err("unknown packet code".to_owned()),
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
    pub fn marshal_binary(&self) -> Result<Vec<u8>, String> {
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
        debug!("{:?}", bs);
        Ok(bs)
    }

    pub fn is_authentic_response(response: Vec<u8>, request: Vec<u8>, secret: Vec<u8>) -> bool {
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
                &response[RADIUS_PACKET_HEADER_LENGTH..], // TODO length
                &secret,
            ]
            .concat(),
        )
        .to_vec()
        .eq(&response[4..RADIUS_PACKET_HEADER_LENGTH].to_vec())
    }

    pub fn is_authentic_request(request: &[u8], secret: &[u8]) -> bool {
        if request.len() < RADIUS_PACKET_HEADER_LENGTH || secret.is_empty() {
            return false;
        }

        match Code::from(request[0]) {
            Code::AccessRequest | Code::StatusServer => true,
            Code::AccountingRequest | Code::DisconnectRequest | Code::CoARequest => {
                md5::compute(
                    [
                        &request[..4],
                        &[
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00,
                        ],
                        &request[RADIUS_PACKET_HEADER_LENGTH..], // TODO length
                        &secret,
                    ]
                    .concat(),
                )
                .to_vec()
                .eq(&request[4..RADIUS_PACKET_HEADER_LENGTH].to_vec())
            }
            _ => false,
        }
    }

    pub fn add(&mut self, typ: AVPType, attr: &Attribute) {
        self.attributes.add(typ, attr.clone());
    }

    pub fn delete(&mut self, typ: AVPType) {
        self.attributes.del(typ);
    }

    pub fn lookup(&self, typ: AVPType) -> Option<&Attribute> {
        self.attributes.lookup(typ)
    }

    pub fn lookup_all(&self, typ: AVPType) -> Vec<&Attribute> {
        self.attributes.lookup_all(typ)
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
            0x01, 0x00, 0x00, 0x38, 0x0f, 0x40, 0x3f, 0x94, 0x73, 0x97, 0x80, 0x57, 0xbd, 0x83,
            0xd5, 0xcb, 0x98, 0xf4, 0x22, 0x7a, 0x01, 0x06, 0x6e, 0x65, 0x6d, 0x6f, 0x02, 0x12,
            0x0d, 0xbe, 0x70, 0x8d, 0x93, 0xd4, 0x13, 0xce, 0x31, 0x96, 0xe4, 0x3f, 0x78, 0x2a,
            0x0a, 0xee, 0x04, 0x06, 0xc0, 0xa8, 0x01, 0x10, 0x05, 0x06, 0x00, 0x00, 0x00, 0x03,
        ];

        let packet = Packet::parse(&request, &secret)?;
        assert_eq!(packet.code, Code::AccessRequest);
        assert_eq!(packet.identifier, 0);

        // TODO

        Ok(())
    }
}
