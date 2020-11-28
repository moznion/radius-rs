use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::string::FromUtf8Error;

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
    #[error("unexpected decoding error: {0}")]
    UnexpectedDecodingError(String),
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

        let l = plain_text.len();
        if l < 16 {
            let enc = md5::compute([secret, &buff[..]].concat()).to_vec();
            return Ok(AVP {
                typ,
                value: enc
                    .iter()
                    .zip([plain_text, vec![0 as u8; 16 - l].as_slice()].concat())
                    //                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ zero padding
                    .map(|(d, p)| d ^ p)
                    .collect(),
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

    pub fn decode_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.value.to_vec())
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
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::string::FromUtf8Error;

    use crate::avp::{AVPError, AVP};
    use chrono::Utc;

    #[test]
    fn it_should_convert_attribute_to_integer32() -> Result<(), AVPError> {
        let given_u32 = 16909060;
        let avp = AVP::encode_u32(1, given_u32);
        assert_eq!(avp.decode_u32()?, given_u32);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_string() -> Result<(), FromUtf8Error> {
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
}
