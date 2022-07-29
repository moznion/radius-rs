use std::fmt;
use std::convert::TryFrom;
use num_enum::TryFromPrimitive;

///! From https://datatracker.ietf.org/doc/html/rfc2284
/// 
// A summary of the Request and Response packet format is shown below.
// The fields are transmitted from left to right.
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Code      |  Identifier   |            Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |  Type-Data ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
// Code
//    1 for Request;
//    2 for Response.
// Identifier
//    The Identifier field is one octet.  The Identifier field MUST be
//    the same if a Request packet is retransmitted due to a timeout
//    while waiting for a Response.  Any new (non-retransmission)
//    Requests MUST modify the Identifier field.  If a peer recieves a
//    duplicate Request for which it has already sent a Response, it
//    MUST resend it's Response.  If a peer receives a duplicate Request
//    before it has sent a Response to the initial Request (i.e. it's
//    waiting for user input), it MUST silently discard the duplicate
//    Request.
// Length
//    The Length field is two octets and indicates the length of the EAP
//    packet including the Code, Identifier, Length, Type, and Type-Data
//    fields.  Octets outside the range of the Length field should be
//    treated as Data Link Layer padding and should be ignored on
//    reception.
// Type
//    The Type field is one octet.  This field indicates the Type of
//    Request or Response.  Only one Type MUST be specified per EAP
//    Request or Response.  Normally, the Type field of the Response
//    will be the same as the Type of the Request.  However, there is
//    also a Nak Response Type for indicating that a Request type is
//    unacceptable to the peer.  When sending a Nak in response to a
//    Request, the peer MAY indicate an alternative desired
//    authentication Type which it supports. An initial specification of
//    Types follows in a later section of this document.
// Type-Data
//    The Type-Data field varies with the Type of Request and the
//    associated Response.
///!

#[derive(Debug, Copy, Clone, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum EAPCode {
    Request  = 1,
    Response = 2,
    Success  = 3,
    Failure  = 4,
    Invalid  = 0,
}

impl EAPCode {
    pub fn string(&self) -> &'static str {
        match self {
            EAPCode::Request  => "EAP-Request",
            EAPCode::Response => "EAP-Response",
            EAPCode::Success  => "EAP-Success",
            EAPCode::Failure  => "EAP-Failure",
            EAPCode::Invalid  => "EAP-Invalid",
        }
    }
    pub fn from(value: u8) -> Self {
        match EAPCode::try_from(value) {
            Ok(code) => code,
            Err(_) => EAPCode::Invalid,
        }
    }
}
//
// This section defines the initial set of EAP Types used in
// Request/Response exchanges.  More Types may be defined in follow-on
// documents.  The Type field is one octet and identifies the structure
// of an EAP Request or Response packet.  The first 3 Types are
// considered special case Types.  The remaining Types define
// authentication exchanges.  The Nak Type is valid only for Response
// packets, it MUST NOT be sent in a Request.  The Nak Type MUST only be
// sent in repsonse to a Request which uses an authentication Type code.
// All EAP implementatins MUST support Types 1-4.  These Types, as well
// as types 5 and 6, are defined in this document.  Follow-on RFCs will
// define additional EAP Types.

//    1       Identity
//    2       Notification
//    3       Nak (Response only)
//    4       MD5-Challenge
//    5       One-Time Password (OTP) (RFC 1938)
//    6       Generic Token Card
//
#[derive(Debug, Copy, Clone, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum EAPType {
    Identity = 1,
    Notification = 2,
    Nak = 3,
    MD5Challenge = 4,
    OneTimePass = 5,
    TokenCard = 6,
    Invalid = 0
}

impl EAPType {
    pub fn string(&self) -> &'static str {
        match self {
            EAPType::Identity => "EAP-Identity",
            EAPType::Notification => "EAP-Notification",
            EAPType::Nak => "EAP-Nak",
            EAPType::MD5Challenge => "EAP-MD5Challenge",
            EAPType::OneTimePass => "EAP-OneTimePass",
            EAPType::TokenCard => "EAP-TokenCard",
            EAPType::Invalid => "EAP-Invalid",
        }
    }
    pub fn from(value: u8) -> Self {
        match EAPType::try_from(value) {
            Ok(code) => code,
            Err(_) => EAPType::Invalid,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EAP {
    pub code: EAPCode,
    pub id: u8,
    pub len: u16,
    pub typ: EAPType,
    pub data: Vec<u8>
}

impl EAP {
    /// Create an (invalid) EAP message structure
    pub fn new() -> Self {
        EAP {
            code: EAPCode::from(0),
            id: 0,
            len: 5, // min size of fields with empty data
            typ: EAPType::from(0),
            data: vec![]
        }
    }
    /// Create an EAP message structure from a slice of bytes
    pub fn from_bytes(eap_bytes: &[u8]) -> Self {
        let code = EAPCode::from(eap_bytes[0]);
        let id   = eap_bytes[1].to_owned();
        let len  = Self::len_from_bytes(&eap_bytes[2..4]);
        let typ  = EAPType::from(eap_bytes[4]);
        let data = eap_bytes[5..(len as usize)].to_owned();
        EAP { code, id, len, typ, data }
    }
    /// Create wire-level byte structure from EAP message
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        bytes.push(self.code as u8);
        bytes.push(self.id);
        bytes.extend(Self::len_to_bytes(self.len));
        bytes.push(self.typ as u8);
        bytes.extend(self.data.clone());
        return bytes
    }
    /// Provide updated value for length field based on current data
    pub fn recalc_len(&self) -> u16 {
        (5 + self.data.len()) as u16
    }
    /// Create a response message of the requested type from current state
    fn len_from_bytes(bytes: &[u8]) -> u16 {
        ((bytes[0] as u16) << 8) | bytes[1] as u16
    }
    /// Format the raw pair of bytes in an EAP message buffer into an appropriate u16
    fn len_to_bytes(len: u16) -> [u8; 2] {
        [(len >> 8) as u8, len as u8]
    }
}

impl fmt::Display for EAP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Code: {}, ID: {}, Length: {}, Type: {}, Data Length: {}",
            self.code.string(), self.id, self.len, self.typ.string(), self.data.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use crate::core::eap::*;

    #[test]
    fn it_should_decode_eap_id() -> Result<(), ()> {
        let eap_bytes = hex::decode("027200090174657374").unwrap();
        let eap = EAP::from_bytes(&eap_bytes[..]);
        assert_eq!(114, eap.id);
        Ok(())
    }
    #[test]
    fn it_should_decode_eap_type() -> Result<(), ()> {
        let eap_bytes = hex::decode("027200090174657374").unwrap();
        let eap = EAP::from_bytes(&eap_bytes[..]);
        assert_eq!(EAPType::Identity, eap.typ);
        Ok(())
    }
    #[test]
    fn it_should_decode_eap_code() -> Result<(), ()> {
        let eap_bytes = hex::decode("027200090174657374").unwrap();
        let eap = EAP::from_bytes(&eap_bytes[..]);
        assert_eq!(EAPCode::Response, eap.code);
        Ok(())
    }
    #[test]
    fn it_should_decode_eap_data() -> Result<(), ()> {
        let eap_bytes = hex::decode("027200090174657374").unwrap();
        let eap = EAP::from_bytes(&eap_bytes[..]);
        assert_eq!("test".to_owned(), String::from_utf8(eap.data).unwrap());
        Ok(())
    }

    fn it_should_marshal_eap_correctly() -> Result<(),()> {
        let eap_bytes = hex::decode("027200090174657374").unwrap();
        let eap = EAP::from_bytes(&eap_bytes[..]);
        assert_eq!(eap_bytes, eap.to_bytes());
        Ok(())
    }
}