pub(crate) const UNUSED_TAG_VALUE: u8 = 0x00;

#[derive(Debug, PartialEq)]
pub struct Tag {
    pub(crate) value: u8,
}

impl Tag {
    pub fn new(value: u8) -> Self {
        Tag { value }
    }

    pub fn new_unused() -> Self {
        Tag {
            value: UNUSED_TAG_VALUE,
        }
    }

    pub fn get_value(&self) -> u8 {
        self.value
    }

    pub fn is_zero(&self) -> bool {
        self.value == UNUSED_TAG_VALUE
    }

    pub fn is_valid_value(&self) -> bool {
        1 <= self.value && self.value <= 0x1f
    }
}

#[cfg(test)]
mod tests {
    use crate::tag::Tag;

    #[test]
    fn test_is_zero() {
        let tag = Tag { value: 0 };
        assert_eq!(tag.is_zero(), true);
        let tag = Tag { value: 1 };
        assert_eq!(tag.is_zero(), false);
    }

    #[test]
    fn test_is_valid_value() {
        let tag = Tag { value: 1 };
        assert_eq!(tag.is_valid_value(), true);
        let tag = Tag { value: 0 };
        assert_eq!(tag.is_valid_value(), false);
        let tag = Tag { value: 0x20 };
        assert_eq!(tag.is_valid_value(), false);
    }
}
