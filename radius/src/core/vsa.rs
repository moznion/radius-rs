/// VSA trait represents the general vendor-specific struct related methods.
pub trait VSA {
    /// len returns the length of sub-attribute of vendor-specific.
    ///
    /// Ref: RFC 4679 - https://datatracker.ietf.org/doc/html/rfc4679
    /// > Vendor-Length
    /// >
    /// >   The Vendor-Length field is one octet and indicates the length of
    /// >   the entire sub-attribute, including the Vendor-Type,
    /// >   Vendor-Length, and Value fields.
    fn len(&self) -> usize;
    /// is_empty returns whether the VSA is empty or not.
    fn is_empty(&self) -> bool;
    /// message returns the serialized vendor-specific message for AVP.
    fn message(&self) -> Vec<u8>;
}

/// StringVSA represents the VSA according to the RFC 2865.
#[derive(Debug, Clone, PartialEq)]
pub struct StringVSA {
    vendor_id: Vec<u8>,
    vendor_type: u8,
    length: u8,
    value: Vec<u8>,
}

impl StringVSA {
    const BYTE_SIZE_OFFSET: usize = 2;

    pub fn new(vendor_id: i32, vendor_type: u8, value: &str) -> StringVSA {
        StringVSA {
            vendor_id: vendor_id.to_be_bytes().to_vec(),
            vendor_type,
            /*
             * Ref: RFC 4679 - https://datatracker.ietf.org/doc/html/rfc4679
             * > Vendor-Length
             * >
             * >   The Vendor-Length field is one octet and indicates the length of
             * >   the entire sub-attribute, including the Vendor-Type,
             * >   Vendor-Length, and Value fields.
             */
            length: (Self::BYTE_SIZE_OFFSET + value.len()) as u8,
            value: value.as_bytes().to_vec(),
        }
    }

    /// Decode from AVP bytes
    pub fn from_message(b: &[u8]) -> Option<StringVSA> {
      if b.len()<6 {
        None
      } else {
        let vendor_id = b[0..4].to_vec();
        let vendor_type = b[4];
        let length = b[5];
        let value = b[6..].to_vec();
        Some(StringVSA{vendor_id,vendor_type,length,value})
      }
    }

    /// Vendor ID slice
    pub fn vendor_id(&self) -> &[u8] {
      &self.vendor_id
    }

    /// Vendor ID as i32 or 0
    pub fn vendor_id_i32(&self) -> i32 {
      if self.vendor_id.len()==4 {
        let mut b = [0u8;4];
        b.clone_from_slice(&self.vendor_id[0..4]);
        i32::from_be_bytes(b)
      } else {
        0
      }
    }

    /// Vendor type
    pub fn vendor_type(&self) -> u8 {
      self.vendor_type
    }

    /// Value as bytes
    pub fn as_bytes(&self) -> &[u8] {
      &self.value
    }
}

impl VSA for StringVSA {
    fn len(&self) -> usize {
        self.length as usize
    }

    fn is_empty(&self) -> bool {
        self.length == 0
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
    ///   |    Attribute-Specific...
    ///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
    ///
    /// See also: RFC 2865 - https://datatracker.ietf.org/doc/html/rfc2865
    fn message(&self) -> Vec<u8> {
        let total_length: usize = Self::BYTE_SIZE_OFFSET + self.vendor_id.len() + self.value.len();
        let mut result = Vec::with_capacity(total_length);

        result.extend(&self.vendor_id);
        result.extend(vec![self.vendor_type, self.length]);
        result.extend(&self.value);

        result
    }
}

/// TaggedStringVSA represents the VSA which has a tag value.
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedStringVSA {
    vendor_id: Vec<u8>,
    vendor_type: u8,
    length: u8,
    tag: u8,
    value: Vec<u8>,
}

impl TaggedStringVSA {
    const BYTE_SIZE_OFFSET: usize = 3;

    pub fn new(vendor_id: i32, vendor_type: u8, tag: u8, value: &str) -> TaggedStringVSA {
        TaggedStringVSA {
            vendor_id: vendor_id.to_be_bytes().to_vec(),
            vendor_type,
            /*
             * Ref: RFC 4679 - https://datatracker.ietf.org/doc/html/rfc4679
             * > Vendor-Length
             * >
             * >   The Vendor-Length field is one octet and indicates the length of
             * >   the entire sub-attribute, including the Vendor-Type,
             * >   Vendor-Length, and Value fields.
             */
            length: (Self::BYTE_SIZE_OFFSET + value.len()) as u8,
            tag,
            value: value.as_bytes().to_vec(),
        }
    }

    /// Decode from AVP bytes
    pub fn from_message(b: &[u8]) -> Option<TaggedStringVSA> {
      if b.len()<7 {
        None
      } else {
        let vendor_id = b[0..4].to_vec();
        let vendor_type = b[4];
        let length = b[5];
        let tag = b[6];
        let value = b[7..].to_vec();
        Some(TaggedStringVSA{vendor_id,vendor_type,length,tag,value})
      }
    }

    /// Vendor ID slice
    pub fn vendor_id(&self) -> &[u8] {
      &self.vendor_id
    }

    /// Vendor ID as i32 or 0
    pub fn vendor_id_i32(&self) -> i32 {
      if self.vendor_id.len()==4 {
        let mut b = [0u8;4];
        b.clone_from_slice(&self.vendor_id[0..4]);
        i32::from_be_bytes(b)
      } else {
        0
      }
    }

    /// Vendor type
    pub fn vendor_type(&self) -> u8 {
      self.vendor_type
    }

    /// Tag
    pub fn tag(&self) -> u8 {
      self.tag
    }

    /// Value as bytes
    pub fn as_bytes(&self) -> &[u8] {
      &self.value
    }

}

impl VSA for TaggedStringVSA {
    fn len(&self) -> usize {
        self.length as usize
    }

    fn is_empty(&self) -> bool {
        self.length == 0
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
        let total_length: usize = Self::BYTE_SIZE_OFFSET + self.vendor_id.len() + self.value.len();
        let mut result = Vec::with_capacity(total_length);

        result.extend(&self.vendor_id);
        result.extend(vec![self.vendor_type, self.length, self.tag]);
        result.extend(&self.value);

        result
    }
}

#[cfg(test)]
mod string_vsa_tests {
    use crate::core::vsa::{StringVSA, VSA};

    #[test]
    fn it_should_get_len_successfully() {
        let vendor_id = 4874;
        let vsa_type = 65;
        let value = "bar(1000,5441)";
        let vsa = StringVSA::new(vendor_id, vsa_type, value);

        assert_eq!(vsa.len(), 16);
    }

    #[test]
    fn it_should_get_message_successfully() {
        let vendor_id = 4874;
        let vsa_type = 65;
        let value = "bar(1000,5441)";
        let vsa = StringVSA::new(vendor_id, vsa_type, value);

        assert_eq!(
            vsa.message(),
            [0, 0, 19, 10, 65, 16, 98, 97, 114, 40, 49, 48, 48, 48, 44, 53, 52, 52, 49, 41]
        )
    }

    #[test]
    fn decode_encode() {
        let vsa = StringVSA::new(1,2,"test");
        let vsa2 = StringVSA::from_message(&vsa.message()).unwrap();
        assert_eq!(vsa,vsa2);
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

    #[test]
    fn decode_encode() {
        let vsa = TaggedStringVSA::new(1,2,3,"test");
        let vsa2 = TaggedStringVSA::from_message(&vsa.message()).unwrap();
        assert_eq!(vsa,vsa2);
    }
}
