use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::tag::Tag;
use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AVPError {
    #[error(
        "the maximum length of the plain text is 128, but the given value is longer than that"
    )]
    PlainTextMaximumLengthExceededError(),
    #[error("secret hasn't be empty, but the given value is empty")]
    SecretMissingError(),
    #[error("request authenticator has to have 16-bytes payload, but the given value doesn't")]
    InvalidRequestAuthenticatorLength(),
    #[error("invalid attribute length: {0}")]
    InvalidAttributeLengthError(usize),
    // TODO: more meaningful error message
    #[error("unexpected decoding error: {0}")]
    UnexpectedDecodingError(String),
    #[error("invalid salt. the MSB has to be 1, but given value isn't: {0}")]
    InvalidSaltMSBError(u8),
}

pub type AVPType = u8;

pub const TYPE_INVALID: AVPType = 255;

#[derive(Debug, Clone, PartialEq)]
pub struct AVP {
    pub(crate) typ: AVPType,
    pub(crate) value: Vec<u8>,
}

impl AVP {
    pub fn encode_u32(typ: AVPType, value: u32) -> Self {
        AVP {
            typ,
            value: u32::to_be_bytes(value).to_vec(),
        }
    }

    pub fn encode_string(typ: AVPType, value: &str) -> Self {
        AVP {
            typ,
            value: value.as_bytes().to_vec(),
        }
    }

    pub fn encode_bytes(typ: AVPType, value: &[u8]) -> Self {
        AVP {
            typ,
            value: value.to_vec(),
        }
    }

    pub fn encode_ipv4(typ: AVPType, value: &Ipv4Addr) -> Self {
        AVP {
            typ,
            value: value.octets().to_vec(),
        }
    }

    pub fn encode_ipv6(typ: AVPType, value: &Ipv6Addr) -> Self {
        AVP {
            typ,
            value: value.octets().to_vec(),
        }
    }

    pub fn encode_user_password(
        typ: AVPType,
        plain_text: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Self, AVPError> {
        // Call the shared secret S and the pseudo-random 128-bit Request
        // Authenticator RA.  Break the password into 16-octet chunks p1, p2,
        // etc.  with the last one padded at the end with nulls to a 16-octet
        // boundary.  Call the ciphertext blocks c(1), c(2), etc.  We'll need
        // intermediate values b1, b2, etc.
        //
        //    b1 = MD5(S + RA)       c(1) = p1 xor b1
        //    b2 = MD5(S + c(1))     c(2) = p2 xor b2
        //           .                       .
        //           .                       .
        //           .                       .
        //    bi = MD5(S + c(i-1))   c(i) = pi xor bi
        //
        // ref: https://tools.ietf.org/html/rfc2865#section-5.2

        if plain_text.len() > 128 {
            return Err(AVPError::PlainTextMaximumLengthExceededError());
        }

        if secret.is_empty() {
            return Err(AVPError::SecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        let mut buff = request_authenticator.to_vec();

        if plain_text.is_empty() {
            let enc = md5::compute([secret, &buff[..]].concat()).to_vec();
            return Ok(AVP {
                typ,
                value: enc.iter().zip(vec![0; 16]).map(|(d, p)| d ^ p).collect(),
            });
        }

        let mut enc: Vec<u8> = Vec::new();
        for chunk in plain_text.chunks(16) {
            let mut chunk_vec = chunk.to_vec();
            let l = chunk.len();
            if l < 16 {
                chunk_vec.extend(vec![0 as u8; 16 - l]); // zero padding
            }

            let enc_block = md5::compute([secret, &buff[..]].concat()).to_vec();
            buff = enc_block
                .iter()
                .zip(chunk_vec)
                .map(|(d, p)| d ^ p)
                .collect();
            enc.extend(&buff);
        }

        Ok(AVP { typ, value: enc })
    }

    pub fn encode_date(typ: AVPType, dt: &DateTime<Utc>) -> Self {
        AVP {
            typ,
            value: u32::to_be_bytes(dt.timestamp() as u32).to_vec(),
        }
    }

    pub fn encode_tunnel_password(
        typ: AVPType,
        plain_text: &[u8],
        tag: u8,
        salt: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Self, AVPError> {
        /*
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |     Type      |    Length     |     Tag       |   Salt
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     Salt (cont)  |   String ...
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         *    b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
         *    b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
         *                .                      .
         *                .                      .
         *                .                      .
         *    b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)
         *
         *  The resulting encrypted String field will contain
         *  c(1)+c(2)+...+c(i).
         *
         *  https://tools.ietf.org/html/rfc2868#section-3.5
         */

        if request_authenticator.len() > 240 {
            return Err(AVPError::InvalidAttributeLengthError(
                request_authenticator.len(),
            ));
        }

        if salt.len() != 2 {
            return Err(AVPError::InvalidAttributeLengthError(2));
        }

        if salt[0] & 0x80 != 0x80 {
            return Err(AVPError::InvalidSaltMSBError(salt[0]));
        }

        if secret.is_empty() {
            return Err(AVPError::SecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        // NOTE: prepend one byte as a tag and two bytes as a salt
        // TODO: should it separate them to private struct fields?
        let mut enc: Vec<u8> = [vec![tag], salt.to_vec()].concat();

        let mut buff = [request_authenticator, salt].concat();
        if plain_text.is_empty() {
            return Ok(AVP {
                typ,
                value: [
                    enc,
                    md5::compute([secret, &buff[..]].concat())
                        .iter()
                        .zip(vec![0; 16])
                        .map(|(d, p)| d ^ p)
                        .collect::<Vec<u8>>(),
                ]
                .concat(),
            });
        }

        for chunk in plain_text.chunks(16) {
            let mut chunk_vec = chunk.to_vec();
            let l = chunk.len();
            if l < 16 {
                chunk_vec.extend(vec![0 as u8; 16 - l]); // zero padding
            }

            let enc_block = md5::compute([secret, &buff[..]].concat()).to_vec();
            buff = enc_block
                .iter()
                .zip(chunk_vec)
                .map(|(d, p)| d ^ p)
                .collect();
            enc.extend(&buff);
        }

        Ok(AVP { typ, value: enc })
    }

    pub fn decode_u32(&self) -> Result<u32, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        if self.value.len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(self.value.len()));
        }

        let (int_bytes, _) = self.value.split_at(U32_SIZE);
        match int_bytes.try_into() {
            Ok(boxed_array) => Ok(u32::from_be_bytes(boxed_array)),
            Err(e) => Err(AVPError::UnexpectedDecodingError(e.to_string())),
        }
    }

    pub fn decode_string(&self) -> Result<String, AVPError> {
        match String::from_utf8(self.value.to_vec()) {
            Ok(str) => Ok(str),
            Err(e) => Err(AVPError::UnexpectedDecodingError(e.to_string())),
        }
    }

    pub fn decode_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }

    pub fn decode_ipv4(&self) -> Result<Ipv4Addr, AVPError> {
        const IPV4_SIZE: usize = std::mem::size_of::<Ipv4Addr>();
        if self.value.len() != IPV4_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(self.value.len()));
        }

        let (int_bytes, _) = self.value.split_at(IPV4_SIZE);
        match int_bytes.try_into() {
            Ok::<[u8; IPV4_SIZE], _>(boxed_array) => Ok(Ipv4Addr::from(boxed_array)),
            Err(e) => Err(AVPError::UnexpectedDecodingError(e.to_string())),
        }
    }

    pub fn decode_ipv6(&self) -> Result<Ipv6Addr, AVPError> {
        const IPV6_SIZE: usize = std::mem::size_of::<Ipv6Addr>();
        if self.value.len() != IPV6_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(self.value.len()));
        }

        let (int_bytes, _) = self.value.split_at(IPV6_SIZE);
        match int_bytes.try_into() {
            Ok::<[u8; IPV6_SIZE], _>(boxed_array) => Ok(Ipv6Addr::from(boxed_array)),
            Err(e) => Err(AVPError::UnexpectedDecodingError(e.to_string())),
        }
    }

    pub fn decode_user_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Vec<u8>, AVPError> {
        if self.value.len() < 16 || self.value.len() > 128 {
            return Err(AVPError::InvalidAttributeLengthError(self.value.len()));
        }

        if secret.is_empty() {
            return Err(AVPError::SecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        let mut dec: Vec<u8> = Vec::new();
        let mut buff: Vec<u8> = request_authenticator.to_vec();

        // NOTE:
        // It ensures attribute value has 16 bytes length at least because the value is encoded by md5.
        // And this must be aligned by each 16 bytes length.
        for chunk in self.value.chunks(16) {
            let chunk_vec = chunk.to_vec();
            let dec_block = md5::compute([secret, &buff[..]].concat()).to_vec();
            dec.extend(
                dec_block
                    .iter()
                    .zip(&chunk_vec)
                    .map(|(d, p)| d ^ p)
                    .collect::<Vec<u8>>(),
            );
            buff = chunk_vec.clone();
        }

        // remove trailing zero bytes
        match dec.split(|b| *b == 0).next() {
            Some(dec) => Ok(dec.to_vec()),
            None => Ok(vec![]),
        }
    }

    pub fn decode_date(&self) -> Result<DateTime<Utc>, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        if self.value.len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(self.value.len()));
        }

        let (int_bytes, _) = self.value.split_at(U32_SIZE);
        match int_bytes.try_into() {
            Ok(boxed_array) => {
                let timestamp = u32::from_be_bytes(boxed_array);
                Ok(Utc.timestamp(timestamp as i64, 0))
            }
            Err(e) => Err(AVPError::UnexpectedDecodingError(e.to_string())),
        }
    }

    pub fn decode_tunnel_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<(Vec<u8>, Tag), AVPError> {
        if self.value.len() - 3 < 16
            || self.value.len() - 3 > 240
            || (self.value.len() - 3) % 16 != 0
        {
            return Err(AVPError::InvalidAttributeLengthError(self.value.len()));
        }

        if self.value[1] & 0x80 != 0x80 {
            // salt
            return Err(AVPError::InvalidSaltMSBError(self.value[1]));
        }

        if secret.is_empty() {
            return Err(AVPError::SecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        let tag = Tag {
            value: self.value[0],
        };
        let mut dec: Vec<u8> = Vec::new();
        let mut buff: Vec<u8> =
            [request_authenticator.to_vec(), self.value[1..3].to_vec()].concat();

        for chunk in self.value[3..].chunks(16) {
            let chunk_vec = chunk.to_vec();
            let dec_block = md5::compute([secret, &buff[..]].concat()).to_vec();
            dec.extend(
                dec_block
                    .iter()
                    .zip(&chunk_vec)
                    .map(|(d, p)| d ^ p)
                    .collect::<Vec<u8>>(),
            );
            buff = chunk_vec.clone();
        }

        // remove trailing zero bytes
        match dec.split(|b| *b == 0).next() {
            Some(dec) => Ok((dec.to_vec(), tag)),
            None => Ok((vec![], tag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use chrono::Utc;

    use crate::avp::{AVPError, AVP};
    use crate::tag::Tag;

    #[test]
    fn it_should_convert_attribute_to_integer32() -> Result<(), AVPError> {
        let given_u32 = 16909060;
        let avp = AVP::encode_u32(1, given_u32);
        assert_eq!(avp.decode_u32()?, given_u32);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_string() -> Result<(), AVPError> {
        let given_str = "Hello, World";
        let avp = AVP::encode_string(1, given_str);
        assert_eq!(avp.decode_string()?, given_str);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_byte() {
        let given_bytes = b"Hello, World";
        let avp = AVP::encode_bytes(1, given_bytes);
        assert_eq!(avp.decode_bytes(), given_bytes);
    }

    #[test]
    fn it_should_convert_ipv4() -> Result<(), AVPError> {
        let given_ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let avp = AVP::encode_ipv4(1, &given_ipv4);
        assert_eq!(avp.decode_ipv4()?, given_ipv4);
        Ok(())
    }

    #[test]
    fn it_should_convert_ipv6() -> Result<(), AVPError> {
        let given_ipv6 = Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
        );
        let avp = AVP::encode_ipv6(1, &given_ipv6);
        assert_eq!(avp.decode_ipv6()?, given_ipv6);
        Ok(())
    }

    #[test]
    fn it_should_convert_user_password() {
        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        };

        let test_cases = &[
            TestCase {
                plain_text: "",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "abc",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "0123456789abcde",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "0123456789abcdef",
                expected_encoded_len: 16,
            },
            TestCase {
                plain_text: "0123456789abcdef0",
                expected_encoded_len: 32,
            },
            TestCase {
                plain_text: "0123456789abcdef0123456789abcdef0123456789abcdef",
                expected_encoded_len: 48,
            },
        ];

        for test_case in test_cases {
            let user_password_avp_result = AVP::encode_user_password(
                1,
                test_case.plain_text.as_bytes(),
                &secret,
                &request_authenticator,
            );
            let avp = user_password_avp_result.unwrap();
            assert_eq!(avp.value.len(), test_case.expected_encoded_len);

            let decoded_password = avp
                .decode_user_password(&secret, &request_authenticator)
                .unwrap();
            assert_eq!(
                String::from_utf8(decoded_password).unwrap(),
                test_case.plain_text
            );
        }
    }

    #[test]
    fn it_should_convert_date() -> Result<(), AVPError> {
        let now = Utc::now();
        let avp = AVP::encode_date(1, &now);
        assert_eq!(avp.decode_date()?.timestamp(), now.timestamp(),);
        Ok(())
    }

    #[test]
    fn it_should_convert_tunnel_password() -> Result<(), AVPError> {
        let salt: Vec<u8> = vec![0x80, 0xef];
        let tag = Tag { value: 0x1e };
        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        };

        let test_cases = &[
            TestCase {
                plain_text: "",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "abc",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "0123456789abcde",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "0123456789abcdef",
                expected_encoded_len: 16 + 3,
            },
            TestCase {
                plain_text: "0123456789abcdef0",
                expected_encoded_len: 32 + 3,
            },
            TestCase {
                plain_text: "0123456789abcdef0123456789abcdef0123456789abcdef",
                expected_encoded_len: 48 + 3,
            },
        ];

        for test_case in test_cases {
            let user_password_avp_result = AVP::encode_tunnel_password(
                1,
                test_case.plain_text.as_bytes(),
                tag.value,
                &salt,
                &secret,
                &request_authenticator,
            );
            let avp = user_password_avp_result.unwrap();
            assert_eq!(avp.value.len(), test_case.expected_encoded_len);

            let (decoded_password, got_tag) = avp
                .decode_tunnel_password(&secret, &request_authenticator)
                .unwrap();
            assert_eq!(got_tag, tag);
            assert_eq!(
                String::from_utf8(decoded_password).unwrap(),
                test_case.plain_text
            );
        }

        Ok(())
    }
}
