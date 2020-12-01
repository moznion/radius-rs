#[derive(Debug, PartialEq)]
pub struct Tag {
    pub(crate) value: u8,
}

impl Tag {
    pub fn get_value(&self) -> u8 {
        self.value
    }

    pub fn is_zero(&self) -> bool {
        self.value == 0
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
