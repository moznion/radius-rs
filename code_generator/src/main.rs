use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufWriter, Write};
use std::path::Path;
use std::str::FromStr;
use std::{env, io, process};

use getopts::Options;
use inflector::Inflector;
use regex::Regex;

const ATTRIBUTE_KIND: &str = "ATTRIBUTE";
const VALUE_KIND: &str = "VALUE";

const RADIUS_VALUE_TYPE: &str = "u32";

const UESR_PASSWORD_TYPE_OPT: &str = "encrypt=1";

#[derive(Debug)]
struct RadiusAttribute {
    name: String,
    typ: u8,
    value_type: RadiusAttributeValueType,
    is_encrypt: bool,
}

#[derive(Debug)]
struct RadiusValue {
    name: String,
    value: u16,
}

#[derive(Debug, PartialEq)]
enum RadiusAttributeValueType {
    String,
    UserPassword,
    Octets,
    IpAddr,
    Integer,
    VSA,
}

impl FromStr for RadiusAttributeValueType {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "string" => Ok(RadiusAttributeValueType::String),
            "octets" => Ok(RadiusAttributeValueType::Octets),
            "ipaddr" => Ok(RadiusAttributeValueType::IpAddr),
            "integer" => Ok(RadiusAttributeValueType::Integer),
            "vsa" => Ok(RadiusAttributeValueType::VSA),
            _ => Err(()),
        }
    }
}

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} [options] DICT_FILE OUT_FILE", program);
    print!("{}", opts.usage(&brief));
    process::exit(0);
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    let matches = opts
        .parse(&args[1..])
        .unwrap_or_else(|f| panic!(f.to_string()));

    if matches.opt_present("h") {
        print_usage(&program, &opts);
    }

    let dict_file_path = Path::new(&matches.free[0]);
    if !dict_file_path.exists() {
        panic!("no such dictionary file => {}", &matches.free[0]);
    }

    let (radius_attributes, radius_attribute_to_values_map) =
        parse_dict_file(dict_file_path).unwrap();

    let value_defined_attributes_set = radius_attribute_to_values_map
        .keys()
        .collect::<HashSet<&String>>();

    let mut w = BufWriter::new(File::create(&matches.free[1]).unwrap());

    generate_header(&mut w);
    generate_values_code(&mut w, &radius_attribute_to_values_map);
    generate_attributes_code(&mut w, &radius_attributes, &value_defined_attributes_set);
}

fn generate_header(w: &mut BufWriter<File>) {
    let code = b"// Code generated by machine generator; DO NOT EDIT.

use std::net::Ipv4Addr;

use crate::avp::{AVP, AVPType, AVPError};
use crate::packet::Packet;

";

    w.write_all(code).unwrap();
}

fn generate_values_code(
    w: &mut BufWriter<File>,
    attr_to_values_map: &BTreeMap<String, Vec<RadiusValue>>,
) {
    for (attr, values) in attr_to_values_map {
        generate_values_for_attribute_code(w, attr, values);
    }
}

fn generate_values_for_attribute_code(w: &mut BufWriter<File>, attr: &str, values: &[RadiusValue]) {
    let type_name = attr.to_pascal_case();
    w.write_all(
        format!(
            "\npub type {type_name} = {radius_value_type};\n",
            type_name = type_name,
            radius_value_type = RADIUS_VALUE_TYPE
        )
        .as_bytes(),
    )
    .unwrap();
    for v in values {
        w.write_all(
            format!(
                "pub const {type_name_prefix}_{value_name}: {type_name} = {value};\n",
                type_name_prefix = type_name.to_screaming_snake_case(),
                value_name = v.name.to_screaming_snake_case(),
                type_name = type_name,
                value = v.value,
            )
            .as_bytes(),
        )
        .unwrap();
    }
    w.write_all(b"\n").unwrap();
}

fn generate_attributes_code(
    w: &mut BufWriter<File>,
    attrs: &[RadiusAttribute],
    value_defined_attributes_set: &HashSet<&String>,
) {
    for attr in attrs {
        generate_attribute_code(w, attr, &value_defined_attributes_set);
    }
}

fn generate_attribute_code(
    w: &mut BufWriter<File>,
    attr: &RadiusAttribute,
    value_defined_attributes_set: &HashSet<&String>,
) {
    let attr_name = attr.name.clone();
    let type_identifier = format!("{}_TYPE", attr_name.to_screaming_snake_case());
    let type_value = attr.typ;
    let method_identifier = attr_name.to_snake_case();

    generate_common_attribute_code(w, &attr_name, &type_identifier, type_value);
    match attr.value_type {
        RadiusAttributeValueType::String => {
            generate_string_attribute_code(w, &method_identifier, &type_identifier)
        }
        RadiusAttributeValueType::UserPassword => {
            generate_user_password_attribute_code(w, &method_identifier, &type_identifier)
        }
        RadiusAttributeValueType::Octets => {
            generate_octets_attribute_code(w, &method_identifier, &type_identifier)
        }
        RadiusAttributeValueType::IpAddr => {
            generate_ipaddr_attribute_code(w, &method_identifier, &type_identifier)
        }
        RadiusAttributeValueType::Integer => {
            if value_defined_attributes_set.contains(&attr_name) {
                generate_value_defined_integer_attribute_code(
                    w,
                    &method_identifier,
                    &type_identifier,
                    &attr_name.to_pascal_case(),
                );
            } else {
                generate_integer_attribute_code(w, &method_identifier, &type_identifier);
            }
        }
        RadiusAttributeValueType::VSA => generate_vsa_attribute_code(),
    }
}

fn generate_common_attribute_code(
    w: &mut BufWriter<File>,
    attr_name: &str,
    type_identifier: &str,
    type_value: u8,
) {
    let code = format!(
        "
pub const {type_identifier}: AVPType = {type_value};
pub fn delete_{method_identifier}(packet: &mut Packet) {{
    packet.delete({type_identifier});
}}
",
        method_identifier = attr_name.to_snake_case(),
        type_identifier = type_identifier,
        type_value = type_value,
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_string_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "pub fn add_{method_identifier}(packet: &mut Packet, value: &str) {{
    packet.add(AVP::encode_string({type_identifier}, value));
}}
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<String, AVPError>> {{
    packet.lookup({type_identifier}).map(|v| v.decode_string())
}}
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<String>, AVPError> {{
    let mut vec = Vec::new();
    for avp in packet.lookup_all({type_identifier}) {{
        vec.push(avp.decode_string()?)
    }}
    Ok(vec)
}}
",
        method_identifier = method_identifier,
        type_identifier = type_identifier,
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_user_password_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) -> Result<(), AVPError> {{
    packet.add(AVP::encode_user_password({type_identifier}, value, packet.get_secret(), packet.get_authenticator())?);
    Ok(())
}}
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Vec<u8>, AVPError>> {{
    packet.lookup({type_identifier}).map(|v| v.decode_user_password(packet.get_secret(), packet.get_authenticator()))
}}
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Vec<u8>>, AVPError> {{
    let mut vec = Vec::new();
    for avp in packet.lookup_all({type_identifier}) {{
        vec.push(avp.decode_user_password(packet.get_secret(), packet.get_authenticator())?)
    }}
    Ok(vec)
}}
",
        method_identifier = method_identifier,
        type_identifier = type_identifier,
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_octets_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "pub fn add_{method_identifier}(packet: &mut Packet, value: &[u8]) {{
    packet.add(AVP::encode_bytes({type_identifier}, value));
}}
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Vec<u8>> {{
    packet.lookup({type_identifier}).map(|v| v.decode_bytes())
}}
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Vec<Vec<u8>> {{
    let mut vec = Vec::new();
    for avp in packet.lookup_all({type_identifier}) {{
        vec.push(avp.decode_bytes())
    }}
    vec
}}
",
        method_identifier = method_identifier,
        type_identifier = type_identifier,
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_ipaddr_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "pub fn add_{method_identifier}(packet: &mut Packet, value: &Ipv4Addr) {{
    packet.add(AVP::encode_ipv4({type_identifier}, value));
}}
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<Ipv4Addr, AVPError>> {{
    packet.lookup({type_identifier}).map(|v| v.decode_ipv4())
}}
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<Ipv4Addr>, AVPError> {{
    let mut vec = Vec::new();
    for avp in packet.lookup_all({type_identifier}) {{
        vec.push(avp.decode_ipv4()?)
    }}
    Ok(vec)
}}
",
        method_identifier = method_identifier,
        type_identifier = type_identifier,
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
) {
    let code = format!(
        "pub fn add_{method_identifier}(packet: &mut Packet, value: u32) {{
    packet.add(AVP::encode_u32({type_identifier}, value));
}}
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<u32, AVPError>> {{
    packet.lookup({type_identifier}).map(|v| v.decode_u32())
}}
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<u32>, AVPError> {{
    let mut vec = Vec::new();
    for avp in packet.lookup_all({type_identifier}) {{
        vec.push(avp.decode_u32()?)
    }}
    Ok(vec)
}}
",
        method_identifier = method_identifier,
        type_identifier = type_identifier,
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_value_defined_integer_attribute_code(
    w: &mut BufWriter<File>,
    method_identifier: &str,
    type_identifier: &str,
    value_type: &str,
) {
    let code = format!(
        "pub fn add_{method_identifier}(packet: &mut Packet, value: {value_type}) {{
    packet.add(AVP::encode_u32({type_identifier}, value as u32));
}}
pub fn lookup_{method_identifier}(packet: &Packet) -> Option<Result<{value_type}, AVPError>> {{
    packet.lookup({type_identifier}).map(|v| Ok(v.decode_u32()? as {value_type}))
}}
pub fn lookup_all_{method_identifier}(packet: &Packet) -> Result<Vec<{value_type}>, AVPError> {{
    let mut vec = Vec::new();
    for avp in packet.lookup_all({type_identifier}) {{
        vec.push(avp.decode_u32()? as {value_type})
    }}
    Ok(vec)
}}
",
        method_identifier = method_identifier,
        type_identifier = type_identifier,
        value_type = value_type,
    );
    w.write_all(code.as_bytes()).unwrap();
}

fn generate_vsa_attribute_code() {
    // NOP
}

type DictParsed = (Vec<RadiusAttribute>, BTreeMap<String, Vec<RadiusValue>>);

fn parse_dict_file(dict_file_path: &Path) -> Result<DictParsed, String> {
    let line_filter_re = Regex::new(r"^(?:#.*|)$").unwrap();
    let tabs_re = Regex::new(r"\t+").unwrap();
    let trailing_comment_re = Regex::new(r"\s*?#.+?$").unwrap();
    let spaces_re = Regex::new(r"\s+").unwrap();

    let mut radius_attributes: Vec<RadiusAttribute> = Vec::new();
    let mut radius_attribute_to_values: BTreeMap<String, Vec<RadiusValue>> = BTreeMap::new();

    let lines = read_lines(dict_file_path).unwrap();
    for line_result in lines {
        let line = line_result.unwrap();

        if line_filter_re.is_match(line.as_str()) {
            continue;
        }

        let items = tabs_re.split(line.as_str()).collect::<Vec<&str>>();

        if items.len() < 4 {
            return Err("the number of items is lacked in a line".to_owned());
        }

        let kind = items[0];
        match kind {
            ATTRIBUTE_KIND => {
                let attribute_type_leaf = trailing_comment_re.replace(items[3], "").to_string();
                let type_descriptions: Vec<&str> = spaces_re.split(&attribute_type_leaf).collect();

                let mut is_encrypt = false;
                if type_descriptions.len() >= 2 {
                    // TODO consider to extract to a method
                    for type_opt in type_descriptions[1].split(',') {
                        if type_opt == UESR_PASSWORD_TYPE_OPT {
                            is_encrypt = true;
                            continue;
                        }
                    }
                }

                let typ = match RadiusAttributeValueType::from_str(type_descriptions[0]) {
                    Ok(t) => {
                        if t == RadiusAttributeValueType::String && is_encrypt {
                            RadiusAttributeValueType::UserPassword
                        } else {
                            t
                        }
                    }
                    Err(_) => {
                        return Err(format!("invalid type has come => {}", type_descriptions[0]));
                    }
                };

                radius_attributes.push(RadiusAttribute {
                    name: items[1].to_string(),
                    typ: items[2].parse().unwrap(),
                    value_type: typ,
                    is_encrypt,
                });
            }
            VALUE_KIND => {
                let attribute_name = items[1].to_string();
                let name = items[2].to_string();

                let value = trailing_comment_re.replace(items[3], "").to_string();
                let radius_value = RadiusValue {
                    name,
                    value: value.parse().unwrap(),
                };

                match radius_attribute_to_values.get_mut(&attribute_name) {
                    None => {
                        radius_attribute_to_values
                            .insert(attribute_name.clone(), vec![radius_value]);
                    }
                    Some(vec) => {
                        vec.push(radius_value);
                    }
                };
            }
            _ => return Err(format!("unexpected kind has come => {}", kind)),
        }
    }

    Ok((radius_attributes, radius_attribute_to_values))
}
