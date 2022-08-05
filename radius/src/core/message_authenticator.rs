use std::fmt;
use hmac::{Hmac, Mac};
use hmac_md5::Md5;
use crate::core::packet::Packet;
use crate::core::rfc2869;

type HmacMd5 = Hmac<Md5>;

///!
//       A RADIUS client receiving an Access-Accept, Access-Reject or
//       Access-Challenge with a Message-Authenticator attribute present
//       MUST calculate the correct value of the Message-Authenticator and
//       silently discard the packet if it does not match the value sent.
//       This attribute is not required in Access-Requests which include
//       the User-Password attribute, but is useful for preventing attacks
//       on other types of authentication.  This attribute is intended to
//       thwart attempts by an attacker to setup a "rogue" NAS, and perform
//       online dictionary attacks against the RADIUS server.  It does not
//       afford protection against "offline" attacks where the attacker
//       intercepts packets containing (for example) CHAP challenge and
//       response, and performs a dictionary attack against those packets
//       offline.
//       A summary of the Message-Authenticator attribute format is shown
//       below.  The fields are transmitted from left to right.
//        0                   1                   2
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |     Type      |    Length     |     String...
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    Type
//       80 for Message-Authenticator
//    Length
//       18
//    String
//       When present in an Access-Request packet, Message-Authenticator is
//       an HMAC-MD5 [RFC2104] hash of the entire Access-Request packet,
//       including Type, ID, Length and Authenticator, using the shared
//       secret as the key, as follows.
//          Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
//          Request Authenticator, Attributes)
//       When the message integrity check is calculated the signature
//       string should be considered to be sixteen octets of zero.
//       For Access-Challenge, Access-Accept, and Access-Reject packets,
//       the Message-Authenticator is calculated as follows, using the
//       Request-Authenticator from the Access-Request this packet is in
//       reply to:
//          Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
//          Request Authenticator, Attributes)
//       When the message integrity check is calculated the signature
//       string should be considered to be sixteen octets of zero.  The
//       shared secret is used as the key for the HMAC-MD5 message
//       integrity check.  The Message-Authenticator is calculated and
//       inserted in the packet before the Response Authenticator is
//       calculated.
///!

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct MessageAuthenticator {
    pub value: [u8; 16]
}

impl MessageAuthenticator {
    /// Create a new Message-Authenticator from a 16-byte slice
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 16);
        let mut arr = [0u8; 16];
        for (place, element) in arr.iter_mut().zip(bytes.iter()) {
            *place = *element;
        }
        MessageAuthenticator { value: arr }
    }
    /// Create a new Message-Authenticator with zeroed-values
    pub fn new() -> Self {
        MessageAuthenticator { value: [0u8; 16] }
    }
    /// Create a new Message-Authenticator from input packet
    pub fn from_packet(sb: &Packet) -> Self {
        let mut mac = HmacMd5::new_from_slice(sb.get_secret()).unwrap();
        mac.update(&sb.encode().expect("Failed to encode packet for hmac-md5")[..]);
        Self::from_bytes(&mac.finalize().into_bytes()[..])
    }
    /// Create a new Message-Authenticator for an Access-Request RADIUS message.
    /// Since this message type is the start of the HMAC-chain, it hashes itself with
    /// the hash-input RADIUS message having a Message-Authenticator equivalent to the
    /// new() method for this code (all zeroes).
    pub fn from_access_request(pkt: &Packet) -> Self {
        Self::from_packet(
            // zero the existing Message-Authenticator
            &Self::new().authenticate_packet(&pkt).unwrap()
        )
    }
    //       the Message-Authenticator is calculated as follows, using the
    //       Request-Authenticator from the Access-Request this packet is in
    //       reply to:
    //          Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
    //          Request Authenticator, Attributes)
    // TODO: this is producing broken responses
    pub fn for_response(pkt: &Packet) -> Self {
        Self::from_packet(
            // Use th RADIUS Request-Authenticator as the input
            &Self::from_bytes(pkt.get_authenticator())
                .authenticate_packet(&pkt).unwrap()
        )
    }
    /// Attempt to create new Packet with signature buffer from this MessageAuthenticator's
    /// value field.
    pub fn authenticate_packet(&self, pkt: &Packet) -> Result<Packet, std::io::Error> {
        let res = match rfc2869::lookup_message_authenticator(&pkt) {
            Some(req_ma_bytes) => {
                let mut req_bytes = pkt.encode().unwrap();
                let _ = Self::replace_slice(&mut req_bytes, &req_ma_bytes, &self.value[..]);
                Packet::decode(&req_bytes, pkt.get_secret()).unwrap()
            },
            None => {
                let mut res = pkt.clone();
                rfc2869::add_message_authenticator(&mut res, &self.value);
                res
            }
        };
        Ok(res)
    }
    // From https://stackoverflow.com/questions/54150353/how-to-find-and-replace-every-matching-slice-of-bytes-with-another-slice
    fn replace_slice(buf: &mut Vec<u8>, from: &Vec<u8>, to: &[u8]) -> bool {
        let mut found = false;
        for i in 0..=buf.len() - from.len() {
            if buf[i..].starts_with(from) {
                buf[i..(i + from.len())].clone_from_slice(to);
                found = true;
            }
        }
        found
    }
}

impl fmt::Display for MessageAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02X?}", self.value)
    }
}

#[cfg(test)]
mod tests {
    use hex;
    use crate::core::packet::Packet;
    use crate::core::message_authenticator::MessageAuthenticator;
    use crate::core::rfc2869;

    #[test]
    fn it_should_authenticate_access_request() -> Result<(), ()> {
        let msg_bytes = hex::decode("01160049b3a5cd2de262bcdbb589752a212e0b2f01067465737404067f00010105060000000150121ca1999b24d5224ddeca96fd7dabac270706000000014f0b023100090174657374").unwrap();
        let secret = b"somesecretval";
        let req_packet = Packet::decode(&msg_bytes, &secret[..]).unwrap();
        assert_eq!(req_packet.encode().unwrap(), msg_bytes);
        let ma_bytes = rfc2869::lookup_message_authenticator(&req_packet).unwrap();
        let ma = MessageAuthenticator::from_bytes(&ma_bytes);
        let ema = MessageAuthenticator::from_access_request(&req_packet);

        assert_eq!(ma, ema);
        Ok(())
    }
    #[test]
    fn it_should_authenticate_other_access_request() -> Result<(), ()> {
        let msg_bytes = hex::decode("019800436b2bbaa41b9081834827599838d2822001067465737404067f00010105060000000150127524cccba729c4ee2fa9f48c645a15294f0b022a00090174657374").unwrap();
        let secret = b"somesecretval";
        let req_packet = Packet::decode(&msg_bytes, &secret[..]).unwrap();
        assert_eq!(req_packet.encode().unwrap(), msg_bytes);
        let ma_bytes = rfc2869::lookup_message_authenticator(&req_packet).unwrap();
        let ma = MessageAuthenticator::from_bytes(&ma_bytes);
        let ema = MessageAuthenticator::from_access_request(&req_packet);

        assert_eq!(ma, ema);
        Ok(())
    }
}