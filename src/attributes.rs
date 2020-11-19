use crate::attribute::Attribute;

pub type Type = u8;

pub const TYPE_INVALID: Type = 1;

pub struct AVP {
    typ: Type,
    attribute: Attribute,
}

pub struct Attributes(Vec<AVP>);

impl Attributes {
    pub fn parse_attributes(bs: &Vec<u8>) -> Result<Attributes, String> {
        let mut i = 0;
        let mut attrs = Vec::new();

        while bs.len() < i {
            if bs[i..].len() < 2 {
                return Err("short buffer".to_owned());
            }

            let length = bs[i + 1] as usize;
            if length > bs[i..].len() || length < 2 || length > 255 {
                return Err("invalid attribute length".to_owned());
            }

            attrs.push(AVP {
                typ: bs[i + 0],
                attribute: if length > 2 {
                    Attribute(bs[i + 2..].to_vec())
                } else {
                    Attribute(vec![])
                },
            });

            i += length;
        }

        Ok(Attributes(attrs))
    }

    pub fn add(&mut self, typ: Type, attribute: Attribute) {
        self.0.push(AVP {
            typ,
            attribute,
        })
    }
}
