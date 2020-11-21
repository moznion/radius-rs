use std::convert::TryFrom;

use num_enum::TryFromPrimitive;

#[derive(Debug, Clone, PartialEq, TryFromPrimitive)]
#[repr(u8)]
pub enum Code {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    StatusServer = 12,
    StatusClient = 13,
    DisconnectRequest = 40,
    DisconnectACK = 41,
    DisconnectNAK = 42,
    CoARequest = 43,
    CoAACK = 44,
    CoANAK = 45,
    Reserved = 255,
    Invalid = 0,
}

impl Code {
    pub fn string(&self) -> &'static str {
        match self {
            Code::AccessRequest => "Access-Request",
            Code::AccessAccept => "Access-Accept",
            Code::AccessReject => "Access-Reject",
            Code::AccountingRequest => "Accounting-Request",
            Code::AccountingResponse => "Accounting-Response",
            Code::AccessChallenge => "Access-Challenge",
            Code::StatusServer => "Status-Server",
            Code::StatusClient => "Status-Client",
            Code::DisconnectRequest => "Disconnect-Request",
            Code::DisconnectACK => "Disconnect-ACK",
            Code::DisconnectNAK => "Disconnect-NAK",
            Code::CoARequest => "CoA-Request",
            Code::CoAACK => "CoA-ACK",
            Code::CoANAK => "CoA-NAK",
            Code::Reserved => "Reserved",
            Code::Invalid => "Invalid",
        }
    }

    pub fn from(value: u8) -> Self {
        match Code::try_from(value) {
            Ok(code) => code,
            Err(_) => Code::Invalid
        }
    }
}
