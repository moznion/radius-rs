use rand::Rng;
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, TimeZone, Utc};
use thiserror::Error;

use crate::core::tag::{Tag, UNUSED_TAG_VALUE};

#[cfg(all(feature = "md5", feature = "openssl"))]
compile_error!("feature \"md5\" and feature \"openssl\" cannot be enabled at the same time");

#[cfg(feature = "md5")]
use md5::compute;

#[cfg(feature = "openssl")]
use openssl::hash::{hash, MessageDigest};

#[derive(Error, PartialEq, Debug)]
pub enum AVPError {
    /// This error is raised on the length of given plain text for user-password exceeds the maximum limit.
    #[error("the maximum length of the plain text for user-password is 128, but the given value has {0} bytes")]
    UserPasswordPlainTextMaximumLengthExceededError(usize),

    /// This error is raised when the given secret value for a password is empty.
    #[error("secret for password mustn't be empty, but the given value is empty")]
    PasswordSecretMissingError(),

    /// This error is raised when the given request-authenticator for the password doesn't have 16 bytes length exactly.
    #[error("request authenticator for password has to have 16-bytes payload, but the given value doesn't")]
    InvalidRequestAuthenticatorLength(),

    /// This error is raised when attribute length is conflicted with the expected.
    #[error("invalid attribute length: expected={0}, actual={1} bytes")]
    InvalidAttributeLengthError(String, usize),

    /// This error is raised when the tagged-value doesn't have a tag byte.
    #[error("tag value is missing")]
    TagMissingError(),

    /// This error represents AVP decoding error.
    #[error("decoding error: {0}")]
    DecodingError(String),

    /// This error is raised when the MSB of salt is invalid.
    #[error("invalid salt. the MSB has to be 1, but given value isn't: {0}")]
    InvalidSaltMSBError(u8),

    /// This error is raised when a tag is invalid for the tagged-staring value.
    #[error("invalid tag for string value. this must not be zero")]
    InvalidTagForStringValueError(),

    /// This error is raised when a tag is invalid for the tagged-integer value.
    #[error("invalid tag for integer value. this must be less than or equal 0x1f")]
    InvalidTagForIntegerValueError(),

    /// This error is raised when computation of hash fails using openssl hash
    #[error("computation of hash failed: {0}")]
    HashComputationFailed(String),
}

pub type AVPType = u8;

pub const TYPE_INVALID: AVPType = 255;

/// This struct represents a attribute-value pair.
#[derive(Debug, Clone, PartialEq)]
pub struct AVP {
    pub(crate) typ: AVPType,
    pub(crate) value: Vec<u8>,
}

impl AVP {
    /// (This method is for dictionary developers) make an AVP from a u32 value.
    pub fn from_u32(typ: AVPType, value: u32) -> Self {
        AVP {
            typ,
            value: u32::to_be_bytes(value).to_vec(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a u16 value.
    pub fn from_u16(typ: AVPType, value: u16) -> Self {
        AVP {
            typ,
            value: u16::to_be_bytes(value).to_vec(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a tagged u32 value.
    pub fn from_tagged_u32(typ: AVPType, tag: Option<&Tag>, value: u32) -> Self {
        let tag = match tag {
            None => &Tag {
                value: UNUSED_TAG_VALUE,
            },
            Some(tag) => tag,
        };

        AVP {
            typ,
            value: [vec![tag.value], u32::to_be_bytes(value).to_vec()].concat(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a string value.
    pub fn from_string(typ: AVPType, value: &str) -> Self {
        AVP {
            typ,
            value: value.as_bytes().to_vec(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a tagged string value.
    pub fn from_tagged_string(typ: AVPType, tag: Option<&Tag>, value: &str) -> Self {
        match tag {
            None => AVP {
                typ,
                value: value.as_bytes().to_vec(),
            },
            Some(tag) => AVP {
                typ,
                value: [vec![tag.value], value.as_bytes().to_vec()].concat(),
            },
        }
    }

    /// (This method is for dictionary developers) make an AVP from bytes.
    pub fn from_bytes(typ: AVPType, value: &[u8]) -> Self {
        AVP {
            typ,
            value: value.to_vec(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a IPv4 value.
    pub fn from_ipv4(typ: AVPType, value: &Ipv4Addr) -> Self {
        AVP {
            typ,
            value: value.octets().to_vec(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a IPv4-prefix value.
    pub fn from_ipv4_prefix(typ: AVPType, prefix: &[u8]) -> Result<Self, AVPError> {
        let prefix_len = prefix.len();
        if prefix_len != 4 {
            return Err(AVPError::InvalidAttributeLengthError(
                "4 bytes".to_owned(),
                prefix_len,
            ));
        }

        Ok(AVP {
            typ,
            value: [vec![0x00, prefix_len as u8 & 0b00111111], prefix.to_vec()].concat::<u8>(),
        })
    }

    /// (This method is for dictionary developers) make an AVP from a IPv6 value.
    pub fn from_ipv6(typ: AVPType, value: &Ipv6Addr) -> Self {
        AVP {
            typ,
            value: value.octets().to_vec(),
        }
    }

    /// (This method is for dictionary developers) make an AVP from a IPv6-prefix value.
    pub fn from_ipv6_prefix(typ: AVPType, prefix: &[u8]) -> Result<Self, AVPError> {
        let prefix_len = prefix.len();
        if prefix_len > 16 {
            return Err(AVPError::InvalidAttributeLengthError(
                "16 bytes".to_owned(),
                prefix_len,
            ));
        }

        Ok(AVP {
            typ,
            value: [vec![0x00, (prefix_len * 8) as u8], prefix.to_vec()].concat::<u8>(),
        })
    }

    #[cfg(feature = "md5")]
    /// (This method is for dictionary developers) make an AVP from a user-password value.
    /// see also: https://tools.ietf.org/html/rfc2865#section-5.2
    pub fn from_user_password(
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
            return Err(AVPError::UserPasswordPlainTextMaximumLengthExceededError(
                plain_text.len(),
            ));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        let mut buff = request_authenticator.to_vec();

        if plain_text.is_empty() {
            let enc = compute([secret, &buff[..]].concat()).to_vec();
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
                chunk_vec.extend(vec![0; 16 - l]); // zero padding
            }

            let enc_block = compute([secret, &buff[..]].concat()).to_vec();
            buff = enc_block
                .iter()
                .zip(chunk_vec)
                .map(|(d, p)| d ^ p)
                .collect();
            enc.extend(&buff);
        }

        Ok(AVP { typ, value: enc })
    }

    #[cfg(feature = "openssl")]
    /// (This method is for dictionary developers) make an AVP from a user-password value.
    /// see also: https://tools.ietf.org/html/rfc2865#section-5.2
    pub fn from_user_password(
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
            return Err(AVPError::UserPasswordPlainTextMaximumLengthExceededError(
                plain_text.len(),
            ));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        let mut buff = request_authenticator.to_vec();

        if plain_text.is_empty() {
            let hash_val = hash(MessageDigest::md5(), &[secret, &buff[..]].concat());
        let enc_block = if let Err(_err) = hash_val {
            return Err(AVPError::HashComputationFailed(_err.to_string()))
        } else {
            hash_val.unwrap()
        };
            return Ok(AVP {
                typ,
                value: enc_block.iter().zip(vec![0; 16]).map(|(d, p)| d ^ p).collect(),
            });
        }

        let mut enc: Vec<u8> = Vec::new();
        for chunk in plain_text.chunks(16) {
            let mut chunk_vec = chunk.to_vec();
            let l = chunk.len();
            if l < 16 {
                chunk_vec.extend(vec![0; 16 - l]); // zero padding
            }

            let hash_val = hash(MessageDigest::md5(), &[secret, &buff[..]].concat());
            let enc_block = if let Err(_err) = hash_val {
                return Err(AVPError::HashComputationFailed(_err.to_string()));
            } else {
                hash_val.unwrap()
            };
            buff = enc_block
                .iter()
                .zip(chunk_vec)
                .map(|(d, p)| d ^ p)
                .collect();
            enc.extend(&buff);
        }

        Ok(AVP { typ, value: enc })
    }

    /// (This method is for dictionary developers) make an AVP from a date value.
    pub fn from_date(typ: AVPType, dt: &DateTime<Utc>) -> Self {
        AVP {
            typ,
            value: u32::to_be_bytes(dt.timestamp() as u32).to_vec(),
        }
    }

    #[cfg(feature = "md5")]
    /// (This method is for dictionary developers) make an AVP from a tunne-password value.
    /// see also: https://tools.ietf.org/html/rfc2868#section-3.5
    pub fn from_tunnel_password(
        typ: AVPType,
        tag: Option<&Tag>,
        plain_text: &[u8],
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
                "240 bytes".to_owned(),
                request_authenticator.len(),
            ));
        }

        let mut rng = rand::thread_rng();
        let salt: [u8; 2] = [rng.gen::<u8>() | 0x80, rng.gen::<u8>()];

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        // NOTE: prepend one byte as a tag and two bytes as a salt
        // TODO: should it separate them to private struct fields?
        let mut enc: Vec<u8> = [
            vec![tag.map_or(UNUSED_TAG_VALUE, |v| v.value)],
            salt.to_vec(),
        ]
        .concat();

        let mut buff = [request_authenticator, &salt].concat();
        if plain_text.is_empty() {
            return Ok(AVP {
                typ,
                value: [
                    enc,
                    compute([secret, &buff[..]].concat())
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
                chunk_vec.extend(vec![0; 16 - l]); // zero padding
            }

            let enc_block = compute([secret, &buff[..]].concat()).to_vec();
            buff = enc_block
                .iter()
                .zip(chunk_vec)
                .map(|(d, p)| d ^ p)
                .collect();
            enc.extend(&buff);
        }

        Ok(AVP { typ, value: enc })
    }

    #[cfg(feature = "openssl")]
    /// (This method is for dictionary developers) make an AVP from a tunne-password value.
    /// see also: https://tools.ietf.org/html/rfc2868#section-3.5
    pub fn from_tunnel_password(
        typ: AVPType,
        tag: Option<&Tag>,
        plain_text: &[u8],
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
                "240 bytes".to_owned(),
                request_authenticator.len(),
            ));
        }

        let mut rng = rand::thread_rng();
        let salt: [u8; 2] = [rng.gen::<u8>() | 0x80, rng.gen::<u8>()];

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
        }

        if request_authenticator.len() != 16 {
            return Err(AVPError::InvalidRequestAuthenticatorLength());
        }

        // NOTE: prepend one byte as a tag and two bytes as a salt
        // TODO: should it separate them to private struct fields?
        let mut enc: Vec<u8> = [
            vec![tag.map_or(UNUSED_TAG_VALUE, |v| v.value)],
            salt.to_vec(),
        ]
        .concat();

        let mut buff = [request_authenticator, &salt].concat();
        let hash_val = hash(MessageDigest::md5(), &[secret, &buff[..]].concat());
        let enc_block = if let Err(_err) = hash_val {
            return Err(AVPError::HashComputationFailed(_err.to_string()));
        } else {
            hash_val.unwrap()
        };

        if plain_text.is_empty() {
            return Ok(AVP {
                typ,
                value: [
                    enc,
                    enc_block
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
                chunk_vec.extend(vec![0; 16 - l]); // zero padding
            }

            let hash_val = hash(MessageDigest::md5(), &[secret, &buff[..]].concat());
            let enc_block = if let Err(_err) = hash_val {
                return Err(AVPError::HashComputationFailed(_err.to_string()));
            } else {
                hash_val.unwrap()
            };
            buff = enc_block
                .iter()
                .zip(chunk_vec)
                .map(|(d, p)| d ^ p)
                .collect();
            enc.extend(&buff);
        }

        Ok(AVP { typ, value: enc })
    }

    /// (This method is for dictionary developers) encode an AVP into a u32 value.
    pub fn encode_u32(&self) -> Result<u32, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        if self.value.len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{U32_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(U32_SIZE);
        match int_bytes.try_into() {
            Ok(boxed_array) => Ok(u32::from_be_bytes(boxed_array)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into a u16 value.
    pub fn encode_u16(&self) -> Result<u16, AVPError> {
        const U16_SIZE: usize = std::mem::size_of::<u16>();
        if self.value.len() != U16_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{U16_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(U16_SIZE);
        match int_bytes.try_into() {
            Ok(boxed_array) => Ok(u16::from_be_bytes(boxed_array)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into a tag and u32 value.
    pub fn encode_tagged_u32(&self) -> Result<(u32, Tag), AVPError> {
        if self.value.is_empty() {
            return Err(AVPError::TagMissingError());
        }

        let tag = Tag {
            value: self.value[0],
        };

        // ref RFC2868:
        //   Valid values for this field are 0x01 through 0x1F,
        //   inclusive.  If the Tag field is unused, it MUST be zero (0x00)
        if !tag.is_valid_value() && !tag.is_zero() {
            return Err(AVPError::InvalidTagForIntegerValueError());
        }

        const U32_SIZE: usize = std::mem::size_of::<u32>();
        if self.value[1..].len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{} bytes", U32_SIZE + 1),
                self.value.len(),
            ));
        }
        let (int_bytes, _) = self.value[1..].split_at(U32_SIZE);
        match int_bytes.try_into() {
            Ok(boxed_array) => Ok((u32::from_be_bytes(boxed_array), tag)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into a string value.
    pub fn encode_string(&self) -> Result<String, AVPError> {
        match String::from_utf8(self.value.to_vec()) {
            Ok(str) => Ok(str),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into a tag and string value.
    pub fn encode_tagged_string(&self) -> Result<(String, Option<Tag>), AVPError> {
        let string_vec = self.value.to_vec();
        if string_vec.is_empty() {
            return Err(AVPError::TagMissingError());
        }

        let tag = Tag {
            value: string_vec[0],
        };

        // ref RFC2868:
        //   If the value of the Tag field is greater than 0x00
        //   and less than or equal to 0x1F, it SHOULD be interpreted as
        //   indicating which tunnel (of several alternatives) this attribute
        //   pertains.
        if tag.is_valid_value() {
            return match String::from_utf8(string_vec[1..].to_vec()) {
                Ok(str) => Ok((str, Some(tag))),
                Err(e) => Err(AVPError::DecodingError(e.to_string())),
            };
        }

        if tag.is_zero() {
            return Err(AVPError::InvalidTagForStringValueError());
        }

        // ref RFC2868:
        //   If the Tag field is greater than 0x1F, it SHOULD be
        //   interpreted as the first byte of the following String field.
        match String::from_utf8(self.value.to_vec()) {
            Ok(str) => Ok((str, None)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into bytes.
    pub fn encode_bytes(&self) -> Vec<u8> {
        self.value.to_vec()
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4 value.
    pub fn encode_ipv4(&self) -> Result<Ipv4Addr, AVPError> {
        const IPV4_SIZE: usize = std::mem::size_of::<Ipv4Addr>();
        if self.value.len() != IPV4_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{IPV4_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(IPV4_SIZE);
        match int_bytes.try_into() {
            Ok::<[u8; IPV4_SIZE], _>(boxed_array) => Ok(Ipv4Addr::from(boxed_array)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv4-prefix value.
    pub fn encode_ipv4_prefix(&self) -> Result<Vec<u8>, AVPError> {
        match self.value.len() == 6 {
            true => Ok(self.value[2..].to_owned()),
            false => Err(AVPError::InvalidAttributeLengthError(
                "6 bytes".to_owned(),
                self.value.len(),
            )),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv6 value.
    pub fn encode_ipv6(&self) -> Result<Ipv6Addr, AVPError> {
        const IPV6_SIZE: usize = std::mem::size_of::<Ipv6Addr>();
        if self.value.len() != IPV6_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{IPV6_SIZE} bytes"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(IPV6_SIZE);
        match int_bytes.try_into() {
            Ok::<[u8; IPV6_SIZE], _>(boxed_array) => Ok(Ipv6Addr::from(boxed_array)),
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    /// (This method is for dictionary developers) encode an AVP into Ipv6-prefix value.
    pub fn encode_ipv6_prefix(&self) -> Result<Vec<u8>, AVPError> {
        match self.value.len() >= 2 {
            true => Ok(self.value[2..].to_owned()),
            false => Err(AVPError::InvalidAttributeLengthError(
                "2+ bytes".to_owned(),
                self.value.len(),
            )),
        }
    }

    #[cfg(feature = "md5")]
    /// (This method is for dictionary developers) encode an AVP into user-password value as bytes.
    pub fn encode_user_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Vec<u8>, AVPError> {
        if self.value.len() < 16 || self.value.len() > 128 {
            return Err(AVPError::InvalidAttributeLengthError(
                "16 >= bytes && 128 <= bytes".to_owned(),
                self.value.len(),
            ));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
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
            let dec_block = compute([secret, &buff[..]].concat()).to_vec();
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

    #[cfg(feature = "openssl")]
    // (This method is for dictionary developers) encode an AVP into user-password value as bytes.
    pub fn encode_user_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<Vec<u8>, AVPError> {
        if self.value.len() < 16 || self.value.len() > 128 {
            return Err(AVPError::InvalidAttributeLengthError(
                "16 >= bytes && 128 <= bytes".to_owned(),
                self.value.len(),
            ));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
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
            let hash_val = hash(MessageDigest::md5(), &[secret, &buff[..]].concat());
            let dec_block = if let Err(_err) = hash_val {
                return Err(AVPError::HashComputationFailed(_err.to_string()))
            } else {
                hash_val.unwrap()
            };
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

    /// (This method is for dictionary developers) encode an AVP into date value.
    pub fn encode_date(&self) -> Result<DateTime<Utc>, AVPError> {
        const U32_SIZE: usize = std::mem::size_of::<u32>();
        if self.value.len() != U32_SIZE {
            return Err(AVPError::InvalidAttributeLengthError(
                format!("{U32_SIZE}"),
                self.value.len(),
            ));
        }

        let (int_bytes, _) = self.value.split_at(U32_SIZE);
        match int_bytes.try_into() {
            Ok(boxed_array) => {
                let timestamp = u32::from_be_bytes(boxed_array);
                Ok(Utc.timestamp_opt(timestamp as i64, 0).unwrap())
            }
            Err(e) => Err(AVPError::DecodingError(e.to_string())),
        }
    }

    #[cfg(feature = "md5")]
    /// (This method is for dictionary developers) encode an AVP into a tunnel-password value as bytes.
    pub fn encode_tunnel_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<(Vec<u8>, Tag), AVPError> {
        if self.value.len() < 19 || self.value.len() > 243 || (self.value.len() - 3) % 16 != 0 {
            return Err(AVPError::InvalidAttributeLengthError(
                "19 <= bytes && bytes <= 242 && (bytes - 3) % 16 == 0".to_owned(),
                self.value.len(),
            ));
        }

        if self.value[1] & 0x80 != 0x80 {
            // salt
            return Err(AVPError::InvalidSaltMSBError(self.value[1]));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
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
            let dec_block = compute([secret, &buff[..]].concat()).to_vec();
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

    #[cfg(feature = "openssl")]
    /// (This method is for dictionary developers) encode an AVP into a tunnel-password value as bytes.
    pub fn encode_tunnel_password(
        &self,
        secret: &[u8],
        request_authenticator: &[u8],
    ) -> Result<(Vec<u8>, Tag), AVPError> {
        if self.value.len() < 19 || self.value.len() > 243 || (self.value.len() - 3) % 16 != 0 {
            return Err(AVPError::InvalidAttributeLengthError(
                "19 <= bytes && bytes <= 242 && (bytes - 3) % 16 == 0".to_owned(),
                self.value.len(),
            ));
        }

        if self.value[1] & 0x80 != 0x80 {
            // salt
            return Err(AVPError::InvalidSaltMSBError(self.value[1]));
        }

        if secret.is_empty() {
            return Err(AVPError::PasswordSecretMissingError());
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
            let hash_val = hash(MessageDigest::md5(), &[secret, &buff[..]].concat());
            let dec_block = if let Err(_err) = hash_val {
                return Err(AVPError::HashComputationFailed(_err.to_string()))
            } else {
                hash_val.unwrap()
            };
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

    use crate::core::avp::{AVPError, AVP};
    use crate::core::tag::Tag;

    #[test]
    fn it_should_convert_attribute_to_integer32() -> Result<(), AVPError> {
        let given_u32 = 16909060;
        let avp = AVP::from_u32(1, given_u32);
        assert_eq!(avp.encode_u32()?, given_u32);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_integer16() -> Result<(), AVPError> {
        let given_u16 = 65534;
        let avp = AVP::from_u16(1, given_u16);
        assert_eq!(avp.encode_u16()?, given_u16);
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_tagged_integer32() -> Result<(), AVPError> {
        let given_u32 = 16909060;
        let avp = AVP::from_tagged_u32(1, None, given_u32);
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, Tag::new_unused()));

        let tag = Tag::new(2);
        let avp = AVP::from_tagged_u32(1, Some(&tag), given_u32);
        assert_eq!(avp.encode_tagged_u32()?, (given_u32, tag));
        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_string() -> Result<(), AVPError> {
        let given_str = "Hello, World";
        let avp = AVP::from_string(1, given_str);
        assert_eq!(avp.encode_string()?, given_str);
        Ok(())
    }

    #[test]
    fn it_should_convert_tagged_attribute_to_string() -> Result<(), AVPError> {
        let given_str = "Hello, World";
        let avp = AVP::from_tagged_string(1, None, given_str);
        assert_eq!(avp.encode_tagged_string()?, (given_str.to_owned(), None));

        let tag = Tag::new(3);
        let avp = AVP::from_tagged_string(1, Some(&tag), given_str);
        assert_eq!(
            avp.encode_tagged_string()?,
            (given_str.to_owned(), Some(tag))
        );

        let avp = AVP::from_tagged_string(1, Some(&Tag::new_unused()), given_str);
        assert_eq!(
            avp.encode_tagged_string().unwrap_err(),
            AVPError::InvalidTagForStringValueError()
        );

        Ok(())
    }

    #[test]
    fn it_should_convert_attribute_to_byte() {
        let given_bytes = b"Hello, World";
        let avp = AVP::from_bytes(1, given_bytes);
        assert_eq!(avp.encode_bytes(), given_bytes);
    }

    #[test]
    fn it_should_convert_ipv4() -> Result<(), AVPError> {
        let given_ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        let avp = AVP::from_ipv4(1, &given_ipv4);
        assert_eq!(avp.encode_ipv4()?, given_ipv4);
        Ok(())
    }

    #[test]
    fn it_should_convert_ipv6() -> Result<(), AVPError> {
        let given_ipv6 = Ipv6Addr::new(
            0x2001, 0x0db8, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
        );
        let avp = AVP::from_ipv6(1, &given_ipv6);
        assert_eq!(avp.encode_ipv6()?, given_ipv6);
        Ok(())
    }

    #[test]
    fn it_should_convert_user_password() {
        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        }

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
            let user_password_avp_result = AVP::from_user_password(
                1,
                test_case.plain_text.as_bytes(),
                &secret,
                &request_authenticator,
            );
            let avp = user_password_avp_result.unwrap();
            assert_eq!(avp.value.len(), test_case.expected_encoded_len);

            let decoded_password = avp
                .encode_user_password(&secret, &request_authenticator)
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
        let avp = AVP::from_date(1, &now);
        assert_eq!(avp.encode_date()?.timestamp(), now.timestamp(),);
        Ok(())
    }

    #[test]
    fn it_should_convert_tunnel_password() -> Result<(), AVPError> {
        let tag = Tag { value: 0x1e };
        let secret = b"12345".to_vec();
        let request_authenticator = b"0123456789abcdef".to_vec();

        struct TestCase<'a> {
            plain_text: &'a str,
            expected_encoded_len: usize,
        }

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
            let user_password_avp_result = AVP::from_tunnel_password(
                1,
                Some(&tag),
                test_case.plain_text.as_bytes(),
                &secret,
                &request_authenticator,
            );
            let avp = user_password_avp_result.unwrap();
            assert_eq!(avp.value.len(), test_case.expected_encoded_len);

            let (decoded_password, got_tag) = avp
                .encode_tunnel_password(&secret, &request_authenticator)
                .unwrap();
            assert_eq!(got_tag, tag);
            assert_eq!(
                String::from_utf8(decoded_password).unwrap(),
                test_case.plain_text
            );
        }

        Ok(())
    }

    #[test]
    fn should_convert_ipv4_prefix() -> Result<(), AVPError> {
        let prefix = vec![0x01, 0x02, 0x03, 0x04];
        let avp = AVP::from_ipv4_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv4_prefix()?, prefix);

        Ok(())
    }

    #[test]
    fn should_convert_ipv4_prefix_fail_because_of_invalid_prefix_length() {
        let avp = AVP::from_ipv4_prefix(1, &[0x01, 0x02, 0x03]);
        assert_eq!(
            avp.unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 3)
        );

        let avp = AVP::from_ipv4_prefix(1, &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(
            avp.unwrap_err(),
            AVPError::InvalidAttributeLengthError("4 bytes".to_owned(), 5)
        );

        assert_eq!(
            AVP {
                typ: 1,
                value: vec![]
            }
            .encode_ipv4_prefix()
            .unwrap_err(),
            AVPError::InvalidAttributeLengthError("6 bytes".to_owned(), 0)
        );
    }

    #[test]
    fn should_convert_ipv6_prefix() -> Result<(), AVPError> {
        let prefix = vec![];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?, prefix);

        let prefix = vec![0x00, 0x01, 0x02, 0x03];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?, prefix);

        let prefix = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let avp = AVP::from_ipv6_prefix(1, &prefix)?;
        assert_eq!(avp.encode_ipv6_prefix()?, prefix);

        Ok(())
    }

    #[test]
    fn should_convert_ipv6_prefix_fail_because_of_invalid_prefix_length() {
        let avp = AVP::from_ipv6_prefix(
            1,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10,
            ],
        );
        assert_eq!(
            avp.unwrap_err(),
            AVPError::InvalidAttributeLengthError("16 bytes".to_owned(), 17)
        );
    }
}
