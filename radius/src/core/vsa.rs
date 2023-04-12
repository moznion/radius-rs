const SINGLE_FIELDS_COUNT: usize = 3;

/// This struct represents a attribute-value pair.
#[derive(Debug, Clone, PartialEq)]
pub struct VSA {
    vendor_id: Vec<u8>,
    type_id: u8,
    length: u8,
    tag: u8,
    value: Vec<u8>,
}

impl VSA {
    pub fn new(vendor_id: i32, type_id: u8, tag: u8, value: &str) -> VSA {
        VSA {
            vendor_id: vendor_id.to_be_bytes().to_vec(),
            type_id,
            length: (SINGLE_FIELDS_COUNT + value.len()) as u8,
            tag: tag,
            value: value.as_bytes().to_vec(),
        }
    }

    pub fn len(&self) -> usize {
        self.length as usize
    }

    pub fn message(&self) -> Vec<u8> {
        let mut msg = vec![self.type_id, self.length, self.tag];
        msg.splice(0..0, self.vendor_id.iter().cloned());
        msg.append(&mut self.value.clone());

        msg
    }
}
