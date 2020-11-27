use crate::attribute::Attribute;

pub type AVPType = u8;

pub const TYPE_INVALID: AVPType = 255;

#[derive(Debug, Clone, PartialEq)]
pub struct AVP {
    typ: AVPType,
    attribute: Attribute,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attributes(pub(crate) Vec<AVP>);

impl Attributes {
    pub(crate) fn parse_attributes(bs: &[u8]) -> Result<Attributes, String> {
        let mut i = 0;
        let mut attrs = Vec::new();

        while bs.len() > i {
            if bs[i..].len() < 2 {
                return Err("short buffer".to_owned());
            }

            let length = bs[i + 1] as usize;
            if length > bs[i..].len() || length < 2 || length > 255 {
                return Err("invalid attribute length".to_owned());
            }

            attrs.push(AVP {
                typ: bs[i],
                attribute: if length > 2 {
                    Attribute(bs[i + 2..i + length].to_vec())
                } else {
                    Attribute(vec![])
                },
            });

            i += length;
        }

        Ok(Attributes(attrs))
    }

    pub(crate) fn add(&mut self, typ: AVPType, attribute: Attribute) {
        self.0.push(AVP { typ, attribute })
    }

    pub(crate) fn del(&mut self, typ: AVPType) {
        self.0 = self
            .0
            .iter()
            .filter(|&avp| avp.typ != typ)
            .cloned()
            .collect();
    }

    pub(crate) fn lookup(&self, typ: AVPType) -> Option<&Attribute> {
        self.0.iter().find_map(|avp| {
            if avp.typ == typ {
                return Some(&avp.attribute);
            }
            None
        })
    }

    pub(crate) fn lookup_all(&self, typ: AVPType) -> Vec<&Attribute> {
        self.0
            .iter()
            .filter_map(|avp| {
                if avp.typ == typ {
                    Some(&avp.attribute);
                }
                None
            })
            .collect()
    }

    pub fn attributes_encoded_len(&self) -> Result<u16, String> {
        let mut n: u16 = 0;
        for attr in &self.0 {
            let attr_len = attr.attribute.0.len();
            if attr_len > 253 {
                return Err("attribute is too large".to_owned());
            }

            n += 2 + (attr_len as u16);
        }

        Ok(n)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut encoded: Vec<u8> = Vec::new();

        for avp in &self.0 {
            let attr_len = avp.attribute.0.len();
            if attr_len > 253 {
                return Err("attribute is too large".to_owned());
            }
            encoded.push(avp.typ);
            encoded.push(2 + attr_len as u8);
            encoded.extend(&avp.attribute.0);
        }

        Ok(encoded)
    }
}
