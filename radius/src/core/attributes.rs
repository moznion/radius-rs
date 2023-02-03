use crate::core::avp::{AVPType, AVP};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Attributes(pub(crate) Vec<AVP>);

impl Attributes {
    pub(crate) fn decode(bs: &[u8]) -> Result<Attributes, String> {
        let mut i = 0;
        let mut attrs = Vec::new();

        while bs.len() > i {
            if bs[i..].len() < 2 {
                return Err("short buffer".to_owned());
            }

            let length = bs[i + 1] as usize;
            if length > bs[i..].len() || !(2..=255).contains(&length) {
                return Err("invalid attribute length".to_owned());
            }

            attrs.push(AVP {
                typ: bs[i],
                value: if length > 2 {
                    bs[i + 2..i + length].to_vec()
                } else {
                    vec![]
                },
            });

            i += length;
        }

        Ok(Attributes(attrs))
    }

    pub(crate) fn add(&mut self, avp: AVP) {
        self.0.push(avp)
    }

    pub(crate) fn extend(&mut self, avps: Vec<AVP>) {
        self.0.extend(avps)
    }

    pub(crate) fn del(&mut self, typ: AVPType) {
        self.0.retain(|avp| avp.typ != typ);
    }

    pub(crate) fn lookup(&self, typ: AVPType) -> Option<&AVP> {
        self.0.iter().find(|avp| avp.typ == typ)
    }

    pub(crate) fn lookup_all(&self, typ: AVPType) -> Vec<&AVP> {
        self.0.iter().filter(|&avp| avp.typ == typ).collect()
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, String> {
        let mut encoded: Vec<u8> = Vec::new();

        for avp in &self.0 {
            let attr_len = avp.value.len();
            if attr_len > 253 {
                return Err("attribute is too large".to_owned());
            }
            encoded.push(avp.typ);
            encoded.push(2 + attr_len as u8);
            encoded.extend(&avp.value);
        }

        Ok(encoded)
    }
}
