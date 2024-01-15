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
            tag,
            value: value.as_bytes().to_vec(),
        }
    }

    pub fn len(&self) -> usize {
        self.length as usize
    }

    pub fn message(&self) -> Vec<u8> {
        let total_length: usize = SINGLE_FIELDS_COUNT + &self.vendor_id.len() + &self.value.len();
        let mut result = Vec::with_capacity(total_length);

        result.extend(&self.vendor_id);
        result.extend(vec![self.type_id, self.length, self.tag]);
        result.extend(&self.value);

        result
    }
}

#[cfg(test)]
mod tests {
    use crate::core::vsa::VSA;

    #[test]
    fn it_should_get_len_successfully() {
        let vendor_id = 4874;
        let vsa_type = 65;
        let tag = 5;
        let value = "bar(1000,5441)";
        let vsa = VSA::new(vendor_id, vsa_type, tag, value);

        assert_eq!(vsa.len(), 17);
    }

    #[test]
    fn it_should_get_message_successfully() {
        let vendor_id = 4874;
        let vsa_type = 65;
        let tag = 5;
        let value = "bar(1000,5441)";
        let vsa = VSA::new(vendor_id, vsa_type, tag, value);

        assert_eq!(
            vsa.message(),
            [0, 0, 19, 10, 65, 17, 5, 98, 97, 114, 40, 49, 48, 48, 48, 44, 53, 52, 52, 49, 41]
        )
    }
}
