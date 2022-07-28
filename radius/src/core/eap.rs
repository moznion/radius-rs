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
///!
///! From https://datatracker.ietf.org/doc/html/rfc3579#page-14
//    Where the NAS sends an EAP-Request/Identity as the initial packet,
//    the exchange appears as follows:
// Authenticating peer     NAS                    RADIUS server
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
///!
#[derive(Debug, Copy, Clone, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum EAPCode {
    Request = 1,
    Response = 2,
    Invalid = 0,
}

impl EAPCode {
    pub fn string(&self) -> &'static str {
        match self {
            EAPCode::Request => "EAP-Request",
            EAPCode::Response => "EAP-Response",
            EAPCode::Invalid => "EAP-Invalid"
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
    pub fn new() -> Self {
        EAP {
            code: EAPCode::from(0),
            id: 0,
            len: 0,
            typ: EAPType::from(0),
            data: vec![]
        }
    }
    pub fn from_bytes(eap_bytes: &[u8]) -> Self {
        let code = EAPCode::from(eap_bytes[0]);
        let id   = eap_bytes[1].to_owned();
        let len  = Self::len_from_bytes(&eap_bytes[2..4]);
        let typ = EAPType::from(eap_bytes[4]);
        let data = eap_bytes[5..len as usize].to_owned();
        EAP { code, id, len, typ, data }
    }
    fn len_from_bytes(bytes: &[u8]) -> u16 {
        ((bytes[0] as u16) << 8) | bytes[1] as u16
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