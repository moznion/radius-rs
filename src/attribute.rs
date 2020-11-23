use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::string::FromUtf8Error;

use chrono::{DateTime, Utc, TimeZone};

#[derive(Debug, Clone, PartialEq)]
pub struct Attribute(pub(crate) Vec<u8>);

impl Attribute {
    pub fn from_integer32(v: &u32) -> Self {
        Attribute(u32::to_be_bytes(*v).to_vec())
    }

    pub fn from_string(v: &String) -> Self {
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

    pub fn from_user_password(plain_text: &[u8], secret: &[u8], request_authenticator: &[u8]) -> Result<Self, String> {
        if plain_text.len() > 128 {
            return Err("the length of plain_text has to be within 128, but the given value is longer".to_owned());
        }

        if secret.len() == 0 {
            return Err("secret hasn't be empty, but the given value is empty".to_owned());
        }

        if request_authenticator.len() != 16 {
            return Err("request_authenticator has to have 16-bytes payload, but the given value doesn't".to_owned());
        }

        let mut enc: Vec<u8> = Vec::new();

        let digest = md5::compute([&secret[..], &request_authenticator[..]].concat());
        enc.extend(digest.to_vec());

        let (head, _) = plain_text.split_at(16);

        let mut i = 0;
        for b in head {
            enc[i] ^= b;
            i += 1;
        }

        i = 16;
        while i < plain_text.len() {
            let digest = md5::compute([&secret[..], &enc[i - 16..i]].concat());
            enc.extend(digest.to_vec());

            let mut j = 0;
            for b in &plain_text[i..i + 16] { // TODO this has to be 16 bounds, is this correct?
                enc[i + j] ^= b;
                j += 1;
            }

            i += 16;
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

    pub fn to_user_password(&self, secret: &[u8], request_authenticator: &[u8]) -> Result<Vec<u8>, String> {
        if self.0.len() < 16 || self.0.len() > 128 {
            return Err(format!("invalid attribute length {}", self.0.len()));
        }

        if secret.len() == 0 {
            return Err("secret hasn't be empty, but the given value is empty".to_owned());
        }

        if request_authenticator.len() != 16 {
            return Err("request_authenticator has to have 16-bytes payload, but the given value doesn't".to_owned());
        }

        let mut dec: Vec<u8> = Vec::new();

        let digest = md5::compute([&secret[..], &request_authenticator[..]].concat());
        dec.extend(digest.to_vec());

        let (head, _) = self.0.split_at(16);

        let mut i = 0;
        let mut maybe_first_zero_byte_idx = Option::None;
        for b in head {
            dec[i] ^= b;
            if dec[i] == 0 && maybe_first_zero_byte_idx.is_none() {
                maybe_first_zero_byte_idx = Option::Some(i)
            }
            i += 1;
        }

        i = 16;
        while i < self.0.len() {
            let digest = md5::compute([&secret[..], &self.0[i - 16..i]].concat());
            dec.extend(digest.to_vec());

            let mut j = 0;
            for b in &self.0[i..i + 16] { // TODO this has to be 16 bounds, is this correct?
                dec[i + j] ^= b;
                if dec[i + j] == 0 && maybe_first_zero_byte_idx.is_none() {
                    maybe_first_zero_byte_idx = Option::Some(i + j)
                }
                j += 1;
            }

            i += 16;
        }

        match maybe_first_zero_byte_idx {
            None => Ok(dec),
            Some(idx) => Ok(dec[..idx].to_vec())
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

    use crate::attribute::Attribute;
    use chrono::Utc;

    #[test]
    fn it_should_convert_attribute_to_integer32() -> Result<(), String> {
        assert_eq!(Attribute(vec![1, 2, 3, 4]).to_integer32()?, 16909060);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_string() -> Result<(), FromUtf8Error> {
        assert_eq!(
            Attribute(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64]).to_string()?,
            "Hello, World"
        );
        Ok(())
    }

    #[test]
    fn it_should_convert_ipv4() -> Result<(), String> {
        let given_ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let ipv4_attr = Attribute::from_ipv4(&given_ipv4);
        assert_eq!(
            ipv4_attr.to_ipv4()?,
            given_ipv4,
        );
        Ok(())
    }

    #[test]
    fn it_should_convert_ipv6() -> Result<(), String> {
        let given_ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
        let ipv6_attr = Attribute::from_ipv6(&given_ipv6);
        assert_eq!(
            ipv6_attr.to_ipv6()?,
            given_ipv6,
        );
        Ok(())
    }

    #[test]
    fn it_should_convert_user_password() {
        let plain_text = b"texttexttexttexttexttexttexttext".to_vec();
        let secret = b"secret".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();
        let user_password_attr_result = Attribute::from_user_password(&plain_text, &secret, &request_authenticator);
        let user_password_attr = user_password_attr_result.unwrap();
        assert_eq!(
            user_password_attr.0,
            vec![0xb7, 0xb0, 0xcb, 0x5d, 0x4f, 0x96, 0xd4, 0x75, 0x1c, 0xea, 0x3a, 0xb6, 0xf, 0xc, 0xea, 0xa5, 0xc9, 0x22, 0xac, 0x26, 0x28, 0x23, 0x93, 0xef, 0x19, 0x67, 0xcc, 0xeb, 0x9d, 0x33, 0xd7, 0x46],
        );
        assert_eq!(
            user_password_attr.to_user_password(&secret, &request_authenticator).unwrap(),
            plain_text,
        );
    }

    #[test]
    fn it_should_convert_date() -> Result<(), String> {
        let now = Utc::now();
        let attr = Attribute::from_date(&now);
        assert_eq!(
            attr.to_date()?.timestamp(),
            now.timestamp(),
        );
        Ok(())
    }
}
