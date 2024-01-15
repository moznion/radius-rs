const SINGLE_FIELDS_COUNT: usize = 3;

/// VSA trait represents the general vendor-specific struct related methods.
pub trait VSA {
    /// len returns the length of sub-attribute of vendor-specific.
    fn len(&self) -> usize;
    /// message returns the serialized vendor-specific message for AVP.
    fn message(&self) -> Vec<u8>;
}

/// TaggedStringVSA represents the VSA which has a tag value.
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedStringVSA {
    vendor_id: Vec<u8>,
    type_id: u8,
    length: u8,
    tag: u8,
    value: Vec<u8>,
}

impl TaggedStringVSA {
    pub fn new(vendor_id: i32, type_id: u8, tag: u8, value: &str) -> TaggedStringVSA {
        TaggedStringVSA {
            vendor_id: vendor_id.to_be_bytes().to_vec(),
            type_id,
            length: (SINGLE_FIELDS_COUNT + value.len()) as u8,
            tag,
            value: value.as_bytes().to_vec(),
        }
    }
}

impl VSA for TaggedStringVSA {
    /// len returns the length of sub-attribute of vendor-specific.
    ///
    /// Ref: RFC4679 - https://datatracker.ietf.org/doc/html/rfc4679
    /// > Vendor-Length
    /// >
    /// >   The Vendor-Length field is one octet and indicates the length of
    /// >   the entire sub-attribute, including the Vendor-Type,
    /// >   Vendor-Length, and Value fields.
    fn len(&self) -> usize {
        self.length as usize
    }

    /// message returns the serialized vendor-specific message for AVP.
    ///
    /// Format:
    ///    0                   1                   2                   3
    ///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   |    Type       |  Length       |            Vendor-Id
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///        Vendor-Id (cont)           | Vendor type   | Vendor length |
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///   |    Tag        |  Attribute-Specific...
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    ///
    /// See also: CISCO RADIUS Attributes Configuration Guide - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_radatt/configuration/xe-16/sec-usr-radatt-xe-16-book.pdf
    fn message(&self) -> Vec<u8> {
        let total_length: usize = SINGLE_FIELDS_COUNT + &self.vendor_id.len() + &self.value.len();
        let mut result = Vec::with_capacity(total_length);

        result.extend(&self.vendor_id);
        result.extend(vec![self.type_id, self.length, self.tag]);
        result.extend(&self.value);

        result
    }
}

#[cfg(test)]
mod tagged_string_vsa_tests {
    use crate::core::vsa::{TaggedStringVSA, VSA};

    #[test]
    fn it_should_get_len_successfully() {
        let vendor_id = 4874;
        let vsa_type = 65;
        let tag = 5;
        let value = "bar(1000,5441)";
        let vsa = TaggedStringVSA::new(vendor_id, vsa_type, tag, value);

        assert_eq!(vsa.len(), 17);
    }

    #[test]
    fn it_should_get_message_successfully() {
        let vendor_id = 4874;
        let vsa_type = 65;
        let tag = 5;
        let value = "bar(1000,5441)";
        let vsa = TaggedStringVSA::new(vendor_id, vsa_type, tag, value);

        assert_eq!(
            vsa.message(),
            [0, 0, 19, 10, 65, 17, 5, 98, 97, 114, 40, 49, 48, 48, 48, 44, 53, 52, 52, 49, 41]
        )
    }
}
