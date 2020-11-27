use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::string::FromUtf8Error;

use chrono::{DateTime, TimeZone, Utc};

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute(pub(crate) Vec<u8>);

impl Attribute {
    pub fn from_u32(v: u32) -> Self {
        Attribute(u32::to_be_bytes(v).to_vec())
    }

    pub fn from_string(v: &str) -> Self {
        Attribute(v.as_bytes().to_vec())
    }

    pub fn from_bytes(v: &[u8]) -> Self {
        Attribute(v.to_vec())
    }

    pub fn from_ipv4(v: &Ipv4Addr) -> Self {
        Attribute(v.octets().to_vec())
    }

    pub fn from_ipv6(v: &Ipv6Addr) -> Self {
        Attribute(v.octets().to_vec())
    }

    pub fn from_user_password(
        plain_text: &[u8],
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Self, String> {
        if plain_text.len() > 128 {
            return Err(
                "the length of plain_text has to be within 128, but the given value is longer"
                    .to_owned(),
            );
        }

        if secret.is_empty() {
            return Err("secret hasn't be empty, but the given value is empty".to_owned());
        }

        if request_authenticator.len() != 16 {
            return Err(
                "request_authenticator has to have 16-bytes payload, but the given value doesn't"
                    .to_owned(),
            );
        }

        let mut buff = request_authenticator.to_vec();

        let l = plain_text.len();
        if l < 16 {
            let enc = md5::compute([secret, &buff[..]].concat()).to_vec();
            return Ok(Attribute(
                enc.iter()
                    .zip([plain_text, vec![0 as u8; 16 - l].as_slice()].concat())
                    //                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ zero padding
                    .map(|(d, p)| d ^ p)
                    .collect(),
            ));
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

        Ok(Attribute(enc))
    }

    pub fn from_date(dt: &DateTime<Utc>) -> Self {
        Attribute(u32::to_be_bytes(dt.timestamp() as u32).to_vec())
    }

    pub fn to_integer32(&self) -> Result<u32, String> {
        const EXPECTED_SIZE: usize = std::mem::size_of::<u32>();
        if self.0.len() != EXPECTED_SIZE {
            return Err("invalid attribute length for integer".to_owned());
        }

        let (int_bytes, _) = self.0.split_at(EXPECTED_SIZE);
        match int_bytes.try_into() {
            Ok(boxed_array) => Ok(u32::from_be_bytes(boxed_array)),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn to_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.0.to_vec())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn to_ipv4(&self) -> Result<Ipv4Addr, String> {
        const IPV4_SIZE: usize = std::mem::size_of::<Ipv4Addr>();
        if self.0.len() != IPV4_SIZE {
            return Err("invalid attribute length for ipv4 address".to_owned());
        }

        let (int_bytes, _) = self.0.split_at(IPV4_SIZE);
        match int_bytes.try_into() {
            Ok::<[u8; IPV4_SIZE], _>(boxed_array) => Ok(Ipv4Addr::from(boxed_array)),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn to_ipv6(&self) -> Result<Ipv6Addr, String> {
        const IPV6_SIZE: usize = std::mem::size_of::<Ipv6Addr>();
        if self.0.len() != IPV6_SIZE {
            return Err("invalid attribute length for ipv6 address".to_owned());
        }

        let (int_bytes, _) = self.0.split_at(IPV6_SIZE);
        match int_bytes.try_into() {
            Ok::<[u8; IPV6_SIZE], _>(boxed_array) => Ok(Ipv6Addr::from(boxed_array)),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn to_user_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Vec<u8>, String> {
        if self.0.len() < 16 || self.0.len() > 128 {
            return Err(format!("invalid attribute length {}", self.0.len()));
        }

        if secret.is_empty() {
            return Err("secret hasn't be empty, but the given value is empty".to_owned());
        }

        if request_authenticator.len() != 16 {
            return Err(
                "request_authenticator has to have 16-bytes payload, but the given value doesn't"
                    .to_owned(),
            );
        }

        let mut dec: Vec<u8> = Vec::new();
        let mut buff: Vec<u8> = request_authenticator.to_vec();

        // NOTE:
        // It ensures attribute value has 16 bytes length at least because the value is encoded by md5.
        // And this must be aligned by each 16 bytes length.
        for chunk in self.0.chunks(16) {
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

    pub fn to_date(&self) -> Result<DateTime<Utc>, String> {
        let (int_bytes, _) = self.0.split_at(std::mem::size_of::<u32>());
        match int_bytes.try_into() {
            Ok(boxed_array) => {
                let timestamp = u32::from_be_bytes(boxed_array);
                Ok(Utc.timestamp(timestamp as i64, 0))
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::string::FromUtf8Error;

    use chrono::Utc;

    use crate::attribute::Attribute;

    #[test]
    fn it_should_convert_attribute_to_integer32() -> Result<(), String> {
        assert_eq!(Attribute(vec![1, 2, 3, 4]).to_integer32()?, 16909060);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_string() -> Result<(), FromUtf8Error> {
        assert_eq!(
            Attribute(vec![
                0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64
            ])
            .to_string()?,
            "Hello, World"
        );
        Ok(())
    }

    #[test]
    fn it_should_convert_ipv4() -> Result<(), String> {
        let given_ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let ipv4_attr = Attribute::from_ipv4(&given_ipv4);
        assert_eq!(ipv4_attr.to_ipv4()?, given_ipv4,);
        Ok(())
    }

    #[test]
    fn it_should_convert_ipv6() -> Result<(), String> {
        let given_ipv6 = Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
        );
        let ipv6_attr = Attribute::from_ipv6(&given_ipv6);
        assert_eq!(ipv6_attr.to_ipv6()?, given_ipv6,);
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
            let user_password_attr_result = Attribute::from_user_password(
                test_case.plain_text.as_bytes(),
                &secret,
                &request_authenticator,
            );
            let user_password_attr = user_password_attr_result.unwrap();
            assert_eq!(user_password_attr.0.len(), test_case.expected_encoded_len);

            let decoded_password = user_password_attr
                .to_user_password(&secret, &request_authenticator)
                .unwrap();
            assert_eq!(
                String::from_utf8(decoded_password).unwrap(),
                test_case.plain_text
            );
        }
    }

    #[test]
    fn it_should_convert_date() -> Result<(), String> {
        let now = Utc::now();
        let attr = Attribute::from_date(&now);
        assert_eq!(attr.to_date()?.timestamp(), now.timestamp(),);
        Ok(())
    }
}
