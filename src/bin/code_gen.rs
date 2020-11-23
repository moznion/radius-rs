use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::path::Path;
use std::{env, io, process};

use getopts::Options;
use regex::Regex;

const ATTRIBUTE_KIND: &str = "ATTRIBUTE";
const VALUE_KIND: &str = "VALUE";

#[derive(Debug)]
struct RadiusAttribute {
    name: String,
    identifier: u16,
    typ: String,
    is_encrypt: bool,
}

#[derive(Debug)]
struct RadiusValue {
    name: String,
    identifier: u16,
}

fn print_usage(program: &str, opts: &Options) {
    let brief = format!("Usage: {} FILE [options]", program);
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
    let matches = opts
        .parse(&args[1..])
        .unwrap_or_else(|f| panic!(f.to_string()));

    let dict_file_path = matches.free[0].clone();
    let (radius_attributes, radius_attribute_to_values) = parse_dict_file(dict_file_path).unwrap();
    println!("{:?}", radius_attributes);
    println!("{:?}", radius_attribute_to_values);
}

type DictParsed = (Vec<RadiusAttribute>, HashMap<String, Vec<RadiusValue>>);

fn parse_dict_file(dict_file_path: String) -> Result<DictParsed, String> {
    let line_filter_re = Regex::new(r"^(?:#.*|)$").unwrap();
    let tabs_re = Regex::new(r"\t+").unwrap();

    let mut radius_attributes: Vec<RadiusAttribute> = Vec::new();
    let mut radius_attribute_to_values: HashMap<String, Vec<RadiusValue>> = HashMap::new();

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
                let type_descriptions = items[3].split(' ').collect::<Vec<&str>>();
                let typ = type_descriptions[0].to_string();
                let is_encrypt = if type_descriptions.len() >= 2 {
                    type_descriptions[1] == "encrypt=1" // FIXME: ad-hoc!!!
                } else {
                    false
                };

                radius_attributes.push(RadiusAttribute {
                    name: items[1].to_string(),
                    identifier: items[2].parse().unwrap(),
                    typ,
                    is_encrypt,
                });
            }
            VALUE_KIND => {
                let attribute_name = items[1].to_string();
                let name = items[2].to_string();

                let radius_value = RadiusValue {
                    name,
                    identifier: items[3].parse().unwrap(),
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
